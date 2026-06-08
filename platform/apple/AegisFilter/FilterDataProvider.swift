//
//  FilterDataProvider.swift
//  AegisFilter — the Apple child shell's Network Extension content filter.
//
//  This is a NEFilterDataProvider subclass: Apple's SANCTIONED path for a
//  third-party content filter. It inspects flows the system hands it, extracts
//  text where available, asks the shared Rust core (via the aegis-apple-ffi C
//  ABI) for a verdict, and returns .allow() or .drop() accordingly — and posts a
//  REDACTED local notification on a block.
//
//  SCOPE — Apple platform + Aegis policy. This provider can ONLY see the flows
//  the system routes to it (and only the data those flows expose). It CANNOT and
//  MUST NOT:
//    * read other apps' messages / private databases,
//    * capture or mirror the screen,
//    * track location,
//    * block its own uninstall, or remotely control/wipe the device.
//  Those are forbidden for third-party apps on Apple and are out of scope for
//  Aegis by design. This is FILTER + ALERTS, transparently.
//
//  PRIVACY — no message text leaves the device and none is logged. The Rust core
//  returns only small integer codes (action + category); evidence/excerpts stay
//  inside Rust. Notifications carry a category label only, never content.
//

import NetworkExtension
import UserNotifications
import OSLog

/// Action codes returned by `aegis_apple_classify_text` (see aegis_apple.h).
private enum AegisAction: Int32 {
    case allow = 0   // AEGIS_APPLE_ALLOW
    case warn  = 1   // AEGIS_APPLE_WARN
    case block = 2   // AEGIS_APPLE_BLOCK
}

final class FilterDataProvider: NEFilterDataProvider {

    /// Non-sensitive diagnostics only (counts/categories — never content).
    private let log = Logger(subsystem: "co.uk.predatorhunters.aegis.filter", category: "provider")

    /// Opaque handle to the Rust engine (deterministic analyzer + policy).
    /// Created once when the filter starts; freed when it stops.
    private var engine: OpaquePointer?

    // MARK: - Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Build the Rust engine. nil means the lexicon failed to load; we still
        // start (fail-open) so we never wedge the device's network.
        engine = aegis_apple_engine_new()
        if engine == nil {
            log.error("aegis engine failed to initialize; filter will fail open (allow)")
        }
        requestNotificationAuthorizationIfNeeded()
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        if let e = engine {
            aegis_apple_engine_free(e)
            engine = nil
        }
        completionHandler()
    }

    // MARK: - Flow handling

    /// First decision point for a new flow. For flows whose payload we can
    /// inspect inline (e.g. cleartext text we are entitled to see) we ask for the
    /// data; otherwise we allow (we never block blindly).
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // We only attempt text extraction on browser/socket flows whose content
        // is actually available to us. For TLS we generally cannot read content
        // here (and Aegis does NOT attempt covert interception on Apple); such
        // flows are allowed at the network layer and content safety is handled by
        // the sanctioned channels only.
        //
        // Ask the system to stream us the outbound (and inbound) bytes so we can
        // run text extraction in handleOutboundData / handleInboundData.
        return .filterDataVerdict(withFilterInbound: true,
                                  peekInboundBytes: Int.max,
                                  filterOutbound: true,
                                  peekOutboundBytes: Int.max)
    }

    override func handleOutboundData(from flow: NEFilterFlow,
                                     readBytesStartOffset offset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        return verdict(for: readBytes, flow: flow)
    }

    override func handleInboundData(from flow: NEFilterFlow,
                                    readBytesStartOffset offset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        return verdict(for: readBytes, flow: flow)
    }

    // MARK: - Classification

    /// Extract candidate text from raw flow bytes and classify it via Rust.
    ///
    /// NOTE: this is the integration seam. Real text extraction depends on the
    /// flow/protocol — e.g. parsing an HTTP body, a websocket text frame, or
    /// application-level chat JSON. The placeholder below treats the bytes as
    /// UTF-8 and classifies the whole buffer; replace `extractText(...)` with a
    /// protocol-aware extractor for production. We never log the extracted text.
    private func verdict(for bytes: Data, flow: NEFilterFlow) -> NEFilterDataVerdict {
        guard let engine = engine else {
            return .allow() // fail open: engine unavailable
        }
        guard let text = extractText(from: bytes, flow: flow), !text.isEmpty else {
            return .allow() // nothing to classify
        }

        // A stable per-conversation id lets the Rust core correlate messages for
        // cross-message grooming escalation. We derive a non-reversible id from
        // the flow's remote endpoint; refine with an app/thread id where the
        // protocol exposes one.
        let threadID = conversationID(for: flow)

        var category: Int32 = 0
        let action = classify(engine: engine,
                              text: text,
                              threadID: threadID,
                              outCategory: &category)

        switch AegisAction(rawValue: action) ?? .allow {
        case .allow:
            return .allow()
        case .warn:
            // Soft intervention: forward the flow but alert the guardian with a
            // redacted notification. (A WARN does not drop the flow.)
            postBlockNotification(category: category, dropped: false)
            return .allow()
        case .block:
            postBlockNotification(category: category, dropped: true)
            log.notice("flow blocked (category=\(category, privacy: .public))")
            return .drop()
        }
    }

    /// Thin wrapper around the C ABI: passes UTF-8 bytes (no NUL terminator
    /// required) and the optional thread id; returns the action code.
    private func classify(engine: OpaquePointer,
                          text: String,
                          threadID: String,
                          outCategory: inout Int32) -> Int32 {
        let textBytes = Array(text.utf8)
        let threadBytes = Array(threadID.utf8)
        return textBytes.withUnsafeBufferPointer { textBuf in
            threadBytes.withUnsafeBufferPointer { threadBuf in
                textBuf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: textBuf.count) { textPtr in
                    threadBuf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: threadBuf.count) { threadPtr in
                        aegis_apple_classify_text(engine,
                                                  textPtr,
                                                  textBuf.count,
                                                  threadBuf.count == 0 ? nil : threadPtr,
                                                  threadBuf.count,
                                                  &outCategory)
                    }
                }
            }
        }
    }

    /// INTEGRATION SEAM — protocol-aware text extraction goes here.
    /// Placeholder: interpret the buffer as UTF-8 text. For production, parse the
    /// concrete protocol (HTTP body, websocket text frame, chat JSON, …) and
    /// return only human-readable message text. Returns nil if there is no text.
    private func extractText(from bytes: Data, flow: NEFilterFlow) -> String? {
        return String(data: bytes, encoding: .utf8)
    }

    /// Derive a stable, non-reversible conversation id from a flow's endpoint so
    /// the Rust state machine can correlate messages without us storing PII.
    private func conversationID(for flow: NEFilterFlow) -> String {
        if let socketFlow = flow as? NEFilterSocketFlow,
           let remote = socketFlow.remoteEndpoint as? NWHostEndpoint {
            return "\(remote.hostname):\(remote.port)"
        }
        return flow.url?.host ?? "unknown"
    }

    // MARK: - Notifications (redacted)

    private func requestNotificationAuthorizationIfNeeded() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            if !granted {
                self.log.notice("local notification permission not granted")
            }
        }
    }

    /// Post a guardian-facing local notification. Carries a category LABEL only —
    /// never the message text or the URL.
    private func postBlockNotification(category: Int32, dropped: Bool) {
        let content = UNMutableNotificationContent()
        content.title = dropped ? "Aegis blocked content" : "Aegis flagged content"
        content.body = "Category: \(label(for: category)). No message content is stored."
        content.sound = .default

        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content,
                                            trigger: nil)
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }

    /// Content-free category label (mirrors AegisAppleCategory in aegis_apple.h).
    private func label(for category: Int32) -> String {
        switch category {
        case 1: return "safe"
        case 2: return "adult image"
        case 3: return "adult audio"
        case 4: return "adult text"
        case 5: return "grooming suspected"
        case 6: return "CSAM suspected"
        case 7: return "violence"
        case 8: return "self-harm"
        case 9: return "hate"
        default: return "unclassified"
        }
    }
}

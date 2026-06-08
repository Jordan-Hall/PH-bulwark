//
//  BulwarkEngine.swift — a safe Swift wrapper over the bulwark-apple-ffi C ABI.
//
//  This is the unit-testable bridge layer. The NEFilterDataProvider in the Xcode
//  NE target (../../FilterDataProvider.swift) uses the same C ABI directly; this
//  wrapper exists so the bridge logic can be exercised by `swift test` on a Mac
//  without the NetworkExtension entitlement.
//
//  SCOPE: classifies text it is handed. Nothing here reads other apps' data,
//  the screen, or location — filter + alerts only.
//

import CBulwarkApple

/// The action a content filter should take on a classified text span.
public enum BulwarkAction: Int32 {
    case allow = 0
    case warn  = 1
    case block = 2
}

/// A safe, RAII wrapper around the Rust engine handle.
public final class BulwarkEngine {
    private let handle: OpaquePointer

    /// Build a new engine, or return nil if the core failed to initialize.
    public init?() {
        guard let h = bulwark_apple_engine_new() else { return nil }
        self.handle = h
    }

    deinit {
        bulwark_apple_engine_free(handle)
    }

    /// Classify a text span; returns the action and the raw category code.
    /// `threadID` correlates messages in one conversation (pass "" for none).
    public func classify(_ text: String, threadID: String = "") -> (action: BulwarkAction, category: Int32) {
        let textBytes = Array(text.utf8)
        let threadBytes = Array(threadID.utf8)
        var category: Int32 = 0
        let code: Int32 = textBytes.withUnsafeBufferPointer { textBuf in
            threadBytes.withUnsafeBufferPointer { threadBuf in
                textBuf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: textBuf.count) { textPtr in
                    threadBuf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: max(threadBuf.count, 1)) { threadPtr in
                        bulwark_apple_classify_text(handle,
                                                  textPtr,
                                                  textBuf.count,
                                                  threadBuf.count == 0 ? nil : threadPtr,
                                                  threadBuf.count,
                                                  &category)
                    }
                }
            }
        }
        return (BulwarkAction(rawValue: code) ?? .allow, category)
    }
}

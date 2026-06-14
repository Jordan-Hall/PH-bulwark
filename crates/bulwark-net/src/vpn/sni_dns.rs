//! No-Device-Owner host filtering: DNS-name + TLS-SNI matching (NO decryption).
//!
//! This is the **content filter that works on an ordinary consumer phone with no
//! Device Owner and no factory reset**. Without Device Owner we cannot install a
//! trust anchor, so we MUST NOT decrypt TLS — the only host filtering available
//! without decryption is matching the *cleartext* host that two protocols already
//! reveal:
//!
//!   * **DNS** — the queried name is sent in cleartext (UDP/TCP port 53). A query
//!     for a listed host is answered with `NXDOMAIN` (a sinkhole), so the lookup
//!     fails and the app never learns the address.
//!   * **TLS** — the `ClientHello` carries the requested host in the cleartext
//!     **SNI** extension (true for TLS 1.2 *and* 1.3 — the SNI is not encrypted).
//!     We parse it WITHOUT decrypting anything; a listed host's connection is
//!     dropped/reset before the handshake completes.
//!
//! Everything here is **pure** (no I/O, no `unsafe`, no platform `cfg`), so it
//! compiles and is unit-tested on every host (including the Windows dev box,
//! which does NOT compile the `cfg(unix)` pump that calls these). The bug surface
//! is the byte parsing, so that is where the tests are.
//!
//! ## FAIL-SAFE at this layer (deliberate)
//!
//! Every parser returns `None` / every verdict returns [`HostVerdict::Pass`] on
//! ANY malformed, truncated, or unrecognised input. A parse error therefore
//! **passes the traffic** — it never bricks connectivity. This is acceptable
//! **only** because the on-screen **accessibility content filter is the always-on
//! backstop** in the layered protection model: that filter inspects what is
//! actually rendered on the child's screen and does not depend on this network
//! layer. This network filter is an *early, cheap* host block, never the sole
//! gate. (Contrast the decrypting `netstack` pump, which is fail-CLOSED because it
//! is the egress of record there.)
//!
//! ## Honest limits (cannot be filtered here, by design)
//!
//! * **DoH / DoT (encrypted DNS)** — DNS-over-HTTPS (TCP/443 to a resolver) and
//!   DNS-over-TLS (TCP/853) hide the queried name inside TLS, so the plaintext
//!   QNAME match below cannot see it. TODO: detect and refuse known DoH/DoT
//!   resolver endpoints by host (their TLS SNI *is* visible to the SNI filter) so
//!   the device falls back to filterable cleartext DNS. We do NOT attempt to
//!   decrypt encrypted DNS.
//! * **ECH (Encrypted ClientHello)** — when negotiated, the real SNI is encrypted
//!   and only an outer/cover SNI is visible, so [`client_hello_sni`] sees the
//!   cover name. There is no plaintext host to match; such flows pass here and are
//!   covered by the accessibility backstop. We do NOT attempt to decrypt ECH.
#![allow(dead_code)] // Non-unix builds compile the parsers without the pump that calls them.

use crate::blocklist::HostBlocklist;

/// What the host filter decided about one parsed name. `Pass` is the fail-SAFE
/// default returned for any unparseable / unlisted host (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostVerdict {
    /// The host is on the guardian blocklist — refuse it (NXDOMAIN for DNS, reset
    /// for TLS).
    Refuse,
    /// Not listed, or nothing matchable was found — let the traffic through
    /// untouched (the accessibility filter remains the always-on backstop).
    Pass,
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// Offset of the first question in a DNS message (after the 12-byte header).
const DNS_HEADER_LEN: usize = 12;
/// A label-length byte with its top two bits set marks a compression pointer
/// (`0b11xxxxxx`). A *question* never uses compression, so we refuse to chase one
/// (fail-SAFE) rather than implement pointer following.
const DNS_LABEL_PTR_MASK: u8 = 0xC0;
/// Maximum single DNS label length (RFC 1035 §3.1).
const DNS_MAX_LABEL: u8 = 63;

/// Parse the queried name (QNAME) from the FIRST question of a DNS query message.
///
/// `msg` is the raw DNS payload (the UDP body, or a TCP DNS message with its
/// 2-byte length prefix ALREADY stripped by the caller). Returns the dotted host
/// in lowercase, or `None` on any malformed/truncated/compressed input
/// (fail-SAFE → caller passes the query).
///
/// We read exactly one QNAME from the question section; we do NOT follow
/// compression pointers (a question never legally uses them) and we never read a
/// resource record. Every label is bounds- and length-checked.
pub(crate) fn dns_query_name(msg: &[u8]) -> Option<String> {
    if msg.len() < DNS_HEADER_LEN {
        return None;
    }
    // QR bit (high bit of byte 2): only parse QUERIES, not responses.
    if msg[2] & 0x80 != 0 {
        return None;
    }
    // QDCOUNT (bytes 4..6): need at least one question to read a name.
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    read_qname(msg, DNS_HEADER_LEN).map(|(name, _)| name)
}

/// Read a single uncompressed QNAME starting at `pos`. Returns the lowercase
/// dotted name and the offset of the byte AFTER the terminating root label, or
/// `None` on malformed input. ASCII-lowercased so it matches [`HostBlocklist`]
/// (which lowercases its entries).
fn read_qname(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let len_byte = *msg.get(pos)?;
        if len_byte == 0 {
            // Root label terminates the name. An empty QNAME ("." / root) has no
            // host to match → treat as nothing matchable.
            pos += 1;
            return if name.is_empty() {
                None
            } else {
                Some((name, pos))
            };
        }
        // A compression pointer (or the reserved 0b10/0b01 forms) is illegal in a
        // question → fail-SAFE rather than guess.
        if len_byte & DNS_LABEL_PTR_MASK != 0 || len_byte > DNS_MAX_LABEL {
            return None;
        }
        let label_len = len_byte as usize;
        let start = pos + 1;
        let end = start + label_len;
        let label = msg.get(start..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        // DNS labels are conventionally ASCII; lowercase for case-insensitive
        // matching. Non-ASCII bytes are kept verbatim (still byte-comparable).
        for &b in label {
            name.push(b.to_ascii_lowercase() as char);
        }
        pos = end;
    }
}

/// Decide what to do with a captured DNS query payload against `blocklist`.
///
/// Returns [`HostVerdict::Refuse`] only when the queried name is on the
/// blocklist; everything else (empty list, unparseable message, unlisted name)
/// is [`HostVerdict::Pass`] (fail-SAFE). Pure — the caller performs the actual
/// sinkhole injection or forward.
pub(crate) fn dns_verdict(msg: &[u8], blocklist: &HostBlocklist) -> HostVerdict {
    if blocklist.is_empty() {
        return HostVerdict::Pass;
    }
    match dns_query_name(msg) {
        Some(name) if blocklist.is_blocked(&name) => HostVerdict::Refuse,
        _ => HostVerdict::Pass,
    }
}

/// Build a sinkhole `NXDOMAIN` response payload for a DNS query `query`.
///
/// Produces the DNS message a resolver would return for a non-existent name:
/// the query's ID and question are echoed back, the QR bit is set (response),
/// the RD bit is copied from the query, RCODE is `3` (NXDOMAIN), and all answer/
/// authority/additional counts are zeroed (any EDNS OPT record in the query is
/// dropped — we re-emit only the question). The caller wraps this payload in an
/// IP/UDP packet (e.g. `build_dns_response_v4`) sourced from the queried resolver
/// back to the client, so the client's lookup fails cleanly.
///
/// Returns `None` if `query` is too short or its question can't be re-read
/// (fail-SAFE → caller forwards the query instead).
pub(crate) fn build_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_LEN {
        return None;
    }
    // Re-read the (single) question so we copy exactly its bytes — QNAME + the
    // 4-byte QTYPE/QCLASS that follow it — and nothing else.
    let (_name, after_qname) = read_qname(query, DNS_HEADER_LEN)?;
    let question_end = after_qname.checked_add(4)?; // QTYPE(2) + QCLASS(2)
    if question_end > query.len() {
        return None;
    }

    let mut resp = Vec::with_capacity(question_end);
    resp.extend_from_slice(&query[..question_end]);

    // Flags byte 1 (offset 2): set QR (response), keep Opcode (bits 3..6) and the
    // RD bit (bit 0) from the query; clear AA/TC. Byte 2 (offset 3): clear RA/Z,
    // set RCODE=3 (NXDOMAIN).
    let opcode = query[2] & 0x78; // bits 3..6
    let rd = query[2] & 0x01; // recursion desired
    resp[2] = 0x80 | opcode | rd;
    resp[3] = 0x03; // RA=0, Z=0, RCODE=3 (NXDOMAIN)

    // QDCOUNT stays 1 (offsets 4..6, already copied); zero AN/NS/AR counts.
    resp[4] = 0x00;
    resp[5] = 0x01;
    resp[6..12].fill(0);
    Some(resp)
}

// ---------------------------------------------------------------------------
// TLS SNI (ClientHello — cleartext, never decrypted)
// ---------------------------------------------------------------------------

/// TLS record content type for the handshake protocol.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// Handshake message type for a ClientHello.
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// TLS extension type for `server_name` (SNI), RFC 6066.
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
/// SNI `NameType` for `host_name`.
const TLS_SNI_HOST_NAME: u8 = 0x00;

/// Largest accumulated ClientHello we will buffer before giving up (fail-SAFE
/// pass). A real ClientHello is a few hundred bytes to a couple KiB; this bounds
/// memory if a flow sends a huge/garbage handshake length.
pub(crate) const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Whether `buf` could still be the start of a TLS handshake (a ClientHello).
///
/// The peek loop uses this to know when to STOP buffering: the moment the opening
/// bytes can't be a handshake record/ClientHello, there is no cleartext SNI to
/// find, so the caller must fail-SAFE pass IMMEDIATELY rather than wait for more
/// bytes. That matters because a non-TLS request/response protocol (e.g. plain
/// HTTP) sends a short request and then waits for the server's reply — if we kept
/// buffering we'd deadlock the flow (the client won't send more until it's
/// answered, but we haven't dialed the server yet). `true` while the prefix is
/// still consistent with a ClientHello (incl. an empty buffer — nothing seen yet).
pub(crate) fn looks_like_tls_handshake(buf: &[u8]) -> bool {
    // Byte 0 must be the handshake record type; byte 5 (once present) the
    // ClientHello message type. Anything else can carry no SNI → stop peeking.
    if let Some(&first) = buf.first() {
        if first != TLS_RECORD_HANDSHAKE {
            return false;
        }
    }
    match buf.get(5) {
        Some(&msg) => msg == TLS_HANDSHAKE_CLIENT_HELLO,
        None => true, // not enough bytes yet to judge the handshake type
    }
}

/// Parse the SNI `host_name` from a (possibly partial) TLS `ClientHello`.
///
/// `buf` is the cleartext bytes captured at the START of a new TCP flow — the
/// first TLS record(s). NOTHING is decrypted: the SNI travels in the clear in
/// both TLS 1.2 and 1.3. Returns the lowercase host, or `None` if the bytes are
/// not a ClientHello, are still incomplete, carry no SNI extension, or are
/// malformed (all fail-SAFE → caller passes the flow).
///
/// Bounds are re-checked at every hop; the parser can never read out of `buf`.
pub(crate) fn client_hello_sni(buf: &[u8]) -> Option<String> {
    // --- TLS record layer: type(1) version(2) length(2) ---
    if buf.len() < 5 || buf[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // We need enough buffered bytes to cover the handshake we're about to walk;
    // clamp to what's actually present so a short record fails-SAFE rather than
    // reading past `buf`.
    let rec_end = 5usize.checked_add(record_len)?;
    let body = buf.get(5..rec_end.min(buf.len()))?;

    // --- Handshake layer: msg_type(1) length(3) ---
    if body.len() < 4 || body[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let hs_end = 4usize.checked_add(hs_len)?;
    // Incomplete ClientHello (still arriving) → fail-SAFE pass; the caller will
    // have buffered up to MAX_CLIENT_HELLO before calling.
    if hs_end > body.len() {
        return None;
    }
    let mut p = Cursor::new(body.get(4..hs_end)?);

    // client_version(2) + random(32)
    p.skip(2 + 32)?;
    // session_id: u8 length + bytes
    let sid_len = p.u8()? as usize;
    p.skip(sid_len)?;
    // cipher_suites: u16 length + bytes
    let cs_len = p.u16()? as usize;
    p.skip(cs_len)?;
    // compression_methods: u8 length + bytes
    let comp_len = p.u8()? as usize;
    p.skip(comp_len)?;
    // extensions: u16 length + the extension block
    let ext_total = p.u16()? as usize;
    let ext_block = p.take(ext_total)?;

    parse_sni_from_extensions(ext_block)
}

/// Walk the ClientHello extension block looking for `server_name`, then return
/// its first `host_name`. `None` if absent or malformed (fail-SAFE).
fn parse_sni_from_extensions(ext_block: &[u8]) -> Option<String> {
    let mut p = Cursor::new(ext_block);
    while p.remaining() >= 4 {
        let ext_type = p.u16()?;
        let ext_len = p.u16()? as usize;
        let ext_data = p.take(ext_len)?;
        if ext_type == TLS_EXT_SERVER_NAME {
            return parse_server_name_list(ext_data);
        }
    }
    None
}

/// Parse a `ServerNameList`: u16 list length, then `(NameType u8, length u16,
/// name)*`. Return the first `host_name`'s value, lowercased.
fn parse_server_name_list(data: &[u8]) -> Option<String> {
    let mut p = Cursor::new(data);
    let list_len = p.u16()? as usize;
    let mut list = Cursor::new(p.take(list_len)?);
    while list.remaining() >= 3 {
        let name_type = list.u8()?;
        let name_len = list.u16()? as usize;
        let name = list.take(name_len)?;
        if name_type == TLS_SNI_HOST_NAME {
            // SNI host_name is ASCII (IDNA A-labels); reject embedded NUL / empty
            // and lowercase for case-insensitive blocklist matching.
            if name.is_empty() || name.contains(&0) {
                return None;
            }
            let host: String = name
                .iter()
                .map(|&b| b.to_ascii_lowercase() as char)
                .collect();
            return Some(host);
        }
    }
    None
}

/// Decide what to do with the start of a captured TLS flow against `blocklist`.
///
/// [`HostVerdict::Refuse`] only when a parsed SNI host is blocklisted; absent
/// SNI, incomplete bytes, non-TLS, or an unlisted host all yield
/// [`HostVerdict::Pass`] (fail-SAFE). Pure — the caller resets or splices.
pub(crate) fn sni_verdict(buf: &[u8], blocklist: &HostBlocklist) -> HostVerdict {
    if blocklist.is_empty() {
        return HostVerdict::Pass;
    }
    match client_hello_sni(buf) {
        Some(host) if blocklist.is_blocked(&host) => HostVerdict::Refuse,
        _ => HostVerdict::Pass,
    }
}

/// A tiny bounds-checked byte cursor. Every read returns `None` instead of
/// panicking when the buffer is short, so the SNI parser is total over arbitrary
/// (adversarial / truncated) input — the fail-SAFE contract.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Some(u16::from_be_bytes([hi, lo]))
    }

    /// Advance `n` bytes, or `None` if fewer remain.
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    /// Borrow the next `n` bytes and advance, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DNS query-name parsing -------------------------------------------

    /// Build a minimal DNS QUERY for `host` (one A-record question).
    fn dns_query(host: &str) -> Vec<u8> {
        let mut m = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: RD set, QR=0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        for label in host.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0); // root
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        m
    }

    #[test]
    fn parses_simple_qname() {
        assert_eq!(
            dns_query_name(&dns_query("adult.example")).as_deref(),
            Some("adult.example")
        );
        assert_eq!(
            dns_query_name(&dns_query("a.b.c.example.com")).as_deref(),
            Some("a.b.c.example.com")
        );
    }

    #[test]
    fn qname_is_lowercased_to_match_blocklist() {
        assert_eq!(
            dns_query_name(&dns_query("Adult.EXAMPLE")).as_deref(),
            Some("adult.example")
        );
    }

    #[test]
    fn rejects_response_messages() {
        let mut m = dns_query("adult.example");
        m[2] |= 0x80; // set QR (this is a response, not a query)
        assert_eq!(dns_query_name(&m), None);
    }

    #[test]
    fn rejects_zero_question_count() {
        let mut m = dns_query("adult.example");
        m[4] = 0;
        m[5] = 0; // QDCOUNT = 0
        assert_eq!(dns_query_name(&m), None);
    }

    #[test]
    fn rejects_compression_pointer_in_question() {
        // A question must not use compression; a 0xC0 length byte is refused
        // (fail-SAFE) rather than chased.
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 0x0C]); // compression pointer to offset 12
        assert_eq!(dns_query_name(&m), None);
    }

    #[test]
    fn truncated_messages_do_not_panic_and_fail_safe() {
        assert_eq!(dns_query_name(&[]), None);
        assert_eq!(dns_query_name(&[0u8; 5]), None);
        // Header claims a question but the name runs off the end.
        let m = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x05, b'a',
        ];
        assert_eq!(dns_query_name(&m), None);
        // A label length byte over 63 (without the pointer bits) is malformed.
        let m = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x7F, b'a',
        ];
        assert_eq!(dns_query_name(&m), None);
    }

    #[test]
    fn dns_verdict_refuses_only_listed_hosts() {
        let bl = HostBlocklist::parse("adult.example\n.tracker.example");
        assert_eq!(
            dns_verdict(&dns_query("adult.example"), &bl),
            HostVerdict::Refuse
        );
        assert_eq!(
            dns_verdict(&dns_query("x.tracker.example"), &bl),
            HostVerdict::Refuse,
            "suffix rule matches subdomains"
        );
        assert_eq!(
            dns_verdict(&dns_query("safe.example"), &bl),
            HostVerdict::Pass
        );
    }

    #[test]
    fn dns_verdict_empty_list_passes_everything() {
        let bl = HostBlocklist::default();
        assert_eq!(
            dns_verdict(&dns_query("adult.example"), &bl),
            HostVerdict::Pass
        );
    }

    #[test]
    fn dns_verdict_malformed_query_fails_safe() {
        let bl = HostBlocklist::parse("adult.example");
        assert_eq!(dns_verdict(&[0xFF; 4], &bl), HostVerdict::Pass);
    }

    // ---- NXDOMAIN response builder ----------------------------------------

    #[test]
    fn nxdomain_echoes_id_and_question_sets_rcode3() {
        let q = dns_query("adult.example");
        let resp = build_nxdomain_response(&q).expect("builds");
        // ID preserved.
        assert_eq!(&resp[0..2], &q[0..2]);
        // QR set, RD copied, RCODE = 3.
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
        assert_eq!(resp[2] & 0x01, q[2] & 0x01, "RD copied from query");
        assert_eq!(resp[3] & 0x0F, 0x03, "RCODE = NXDOMAIN");
        // Exactly one question, zero answers/authority/additional.
        assert_eq!(&resp[4..6], &[0x00, 0x01]);
        assert_eq!(&resp[6..12], &[0, 0, 0, 0, 0, 0]);
        // The question bytes are echoed verbatim.
        let qlen = q.len(); // our query has exactly one question and no RRs
        assert_eq!(&resp[12..], &q[12..qlen]);
        // It re-parses as the same name.
        let mut as_query = resp.clone();
        as_query[2] &= !0x80; // clear QR so dns_query_name will read it
        assert_eq!(dns_query_name(&as_query).as_deref(), Some("adult.example"));
    }

    #[test]
    fn nxdomain_drops_edns_opt_record() {
        // A query with an OPT (EDNS) record in the additional section: the
        // response must echo ONLY the question and zero the AR count.
        let mut q = dns_query("adult.example");
        q[11] = 0x01; // ARCOUNT = 1
        let opt_start = q.len();
        q.extend_from_slice(&[0x00]); // root name for OPT
        q.extend_from_slice(&[0x00, 0x29]); // TYPE = OPT (41)
        q.extend_from_slice(&[0x10, 0x00]); // UDP payload size
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ext-rcode/flags
        q.extend_from_slice(&[0x00, 0x00]); // RDLEN = 0
        let resp = build_nxdomain_response(&q).expect("builds");
        assert_eq!(&resp[6..12], &[0, 0, 0, 0, 0, 0], "all RR counts zeroed");
        assert_eq!(resp.len(), opt_start, "OPT record not echoed");
    }

    #[test]
    fn nxdomain_fails_safe_on_garbage() {
        assert_eq!(build_nxdomain_response(&[]), None);
        assert_eq!(build_nxdomain_response(&[0u8; 12]), None);
    }

    // ---- TLS ClientHello SNI parsing --------------------------------------

    /// Build a TLS 1.2/1.3-style ClientHello record carrying `sni`.
    fn client_hello(sni: &str) -> Vec<u8> {
        // ServerNameList: NameType(0) + u16 len + host.
        let host = sni.as_bytes();
        let mut server_name = Vec::new();
        server_name.push(TLS_SNI_HOST_NAME);
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);
        // server_name_list: u16 length + the list.
        let mut sni_ext_data = Vec::new();
        sni_ext_data.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(&server_name);
        // extension: type(0x0000) + u16 len + data.
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        // ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0xAB; 32]); // random
        body.push(0x00); // session_id length 0
        body.extend_from_slice(&(2u16).to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(0x01); // compression methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake header: msg_type(1) + length(3).
        let mut hs = Vec::new();
        hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);

        // TLS record header: type(1) + version(2) + length(2).
        let mut rec = Vec::new();
        rec.push(TLS_RECORD_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni_from_client_hello() {
        assert_eq!(
            client_hello_sni(&client_hello("adult.example")).as_deref(),
            Some("adult.example")
        );
    }

    #[test]
    fn sni_is_lowercased() {
        assert_eq!(
            client_hello_sni(&client_hello("Adult.EXAMPLE")).as_deref(),
            Some("adult.example")
        );
    }

    #[test]
    fn non_tls_bytes_fail_safe() {
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(client_hello_sni(&[]), None);
        assert_eq!(client_hello_sni(&[0x16]), None);
    }

    #[test]
    fn looks_like_tls_handshake_gates_the_peek_loop() {
        // Empty / short prefixes can't be ruled out yet → keep peeking.
        assert!(looks_like_tls_handshake(&[]));
        assert!(looks_like_tls_handshake(&[0x16]));
        assert!(looks_like_tls_handshake(&[0x16, 0x03, 0x01, 0x00, 0x05]));
        // A real ClientHello prefix stays plausible.
        let hello = client_hello("safe.example");
        assert!(looks_like_tls_handshake(&hello[..5]));
        assert!(looks_like_tls_handshake(&hello));
        // Non-handshake first byte (plain HTTP) → stop peeking immediately. This
        // is what prevents a non-TLS request/response flow from deadlocking the
        // peek loop while it waits for a server reply that can't come yet.
        assert!(!looks_like_tls_handshake(b"GET / HTTP/1.1\r\n\r\n"));
        // Handshake record byte but a non-ClientHello message type → not us.
        assert!(!looks_like_tls_handshake(&[
            0x16, 0x03, 0x01, 0x00, 0x10, 0x02
        ]));
    }

    #[test]
    fn truncated_client_hello_fails_safe() {
        // A ClientHello that announces more handshake bytes than are present
        // (still arriving) must return None, not panic.
        let full = client_hello("adult.example");
        for cut in 5..full.len() {
            // Never panics, and a partial buffer never yields the SNI.
            assert!(
                client_hello_sni(&full[..cut]).is_none(),
                "partial ClientHello (cut at {cut}) must fail-SAFE, not parse"
            );
        }
        // The complete buffer does yield it.
        assert_eq!(client_hello_sni(&full).as_deref(), Some("adult.example"));
    }

    #[test]
    fn client_hello_without_sni_passes() {
        // Build a ClientHello with an empty extension block → no SNI → None.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0x00);
        body.extend_from_slice(&(0u16).to_be_bytes()); // no cipher suites
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(0u16).to_be_bytes()); // zero-length extensions
        let mut hs = vec![TLS_HANDSHAKE_CLIENT_HELLO];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(client_hello_sni(&rec), None);
    }

    #[test]
    fn sni_verdict_refuses_only_listed_hosts() {
        let bl = HostBlocklist::parse(".adult.example");
        assert_eq!(
            sni_verdict(&client_hello("cdn.adult.example"), &bl),
            HostVerdict::Refuse
        );
        assert_eq!(
            sni_verdict(&client_hello("safe.example"), &bl),
            HostVerdict::Pass
        );
        // Empty list and malformed bytes both pass (fail-SAFE).
        assert_eq!(
            sni_verdict(&client_hello("adult.example"), &HostBlocklist::default()),
            HostVerdict::Pass
        );
        assert_eq!(sni_verdict(b"not tls", &bl), HostVerdict::Pass);
    }
}

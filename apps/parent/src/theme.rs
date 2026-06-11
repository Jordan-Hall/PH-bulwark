//! The console's dark stylesheet — one source of truth, injected once by
//! `router::ConsoleLayout`.

pub const CSS: &str = r#"
    body { margin: 0; font-family: system-ui, sans-serif; background: #10110f; color: #eceee8; }
    .app, .wrap { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .topbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 18px; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    .sub { color: #9aa0ad; margin: 0 0 20px; font-size: 13px; }
    h2 { font-size: 16px; margin: 0 0 8px; color: #d9ddd2; }
    h3 { font-size: 14px; margin: 0 0 12px; color: #d9ddd2; }
    .status-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 12px; }
    .status-tile { background: #171912; border: 1px solid #2a2e22; border-radius: 8px; padding: 12px; min-width: 0; }
    .status-k { display: block; color: #9aa0ad; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }
    .status-v { display: block; font-weight: 700; font-size: 16px; }
    .status-sub { display: block; color: #8b917f; margin-top: 4px; font-size: 12px; overflow-wrap: anywhere; }
    .warn { color: #e8c36b; }
    .tabs { display: flex; gap: 6px; flex-wrap: wrap; margin: 10px 0 16px; border-bottom: 1px solid #292d24; padding-bottom: 8px; }
    .nav-btn { background: transparent; color: #aeb5a6; border: 1px solid transparent; border-radius: 8px; padding: 8px 11px; font-size: 13px; text-decoration: none; display: inline-block; cursor: pointer; }
    .nav-on { background: #1f2b21; color: #e8f3df; border-color: #38533a; }
    .panel { margin: 0 0 18px; }
    .panel-head { margin-bottom: 12px; }
    .panel-head.split { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
    .steps { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 0 0 14px; }
    .step { display: flex; gap: 10px; align-items: flex-start; border: 1px solid #2a2e22; border-radius: 8px; padding: 10px; background: #151711; }
    .step.done { border-color: #3d5c3f; background: #172018; }
    .step-no { display: inline-grid; place-items: center; flex: 0 0 auto; width: 22px; height: 22px; border-radius: 999px; background: #2f6f3e; color: #eaffea; font-weight: 700; font-size: 12px; }
    .two-col { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .box, .status-card { background: #171912; border: 1px solid #2a2e22; border-radius: 8px; padding: 14px; }
    .seg { display: inline-flex; gap: 4px; background: #11140f; border: 1px solid #292d24; border-radius: 8px; padding: 3px; margin-bottom: 12px; }
    .seg-btn { background: transparent; color: #aeb5a6; padding: 6px 10px; }
    .seg-on { background: #2a3b2b; color: #e8f3df; }
    .field { display: grid; gap: 5px; margin-bottom: 10px; color: #aeb5a6; font-size: 12px; }
    input.url, .field input { width: 100%; box-sizing: border-box; background: #0e100d; border: 1px solid #30362b; color: #eceee8; border-radius: 8px; padding: 9px 10px; font: inherit; }
    .primary, .ghost { font-weight: 600; }
    .primary { background: #2f6f3e; color: #eaffea; }
    .ghost { background: #20241d; color: #d9ddd2; border: 1px solid #343b30; }
    .danger-link { color: #ffd7d7; margin-top: 8px; }
    .hint { color: #9aa0ad; font-size: 12px; margin-top: 8px; }
    .pair-code { margin-top: 12px; background: #11140f; border: 1px dashed #566347; border-radius: 8px; padding: 12px; }
    .code { color: #e8f3df; font-size: 28px; font-weight: 800; letter-spacing: 0; margin: 4px 0; }
    .ok-note { background: #162318; border: 1px solid #36583a; color: #cdefd0; border-radius: 8px; padding: 9px 12px; font-size: 12px; margin-top: 12px; }
    .child-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; border: 1px solid #2a2e22; border-radius: 8px; padding: 12px; margin-bottom: 8px; background: #151711; }
    .server-list { display: grid; gap: 8px; margin-bottom: 12px; }
    .server-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; border: 1px solid #2a2e22; border-radius: 8px; padding: 12px; background: #151711; }
    .server-active { border-color: #3d5c3f; background: #172018; }
    .server-main { display: flex; align-items: flex-start; gap: 10px; flex: 1; min-width: 0; margin: 0; }
    .server-main input { margin-top: 3px; flex: 0 0 auto; }
    .server-badges { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
    .badge { display: inline-flex; align-items: center; border: 1px solid #343b30; color: #aeb5a6; border-radius: 999px; padding: 2px 8px; font-size: 11px; }
    .badge-ok { border-color: #36583a; color: #cdefd0; background: #162318; }
    .badge-warn { border-color: #4a3f17; color: #e8d9a0; background: #2a2410; }
    .add-server { margin-top: 12px; }
    .small-btn { padding: 5px 10px; font-size: 12px; flex: 0 0 auto; }
    .banner { background: #2a2410; border: 1px solid #4a3f17; color: #e8d9a0; border-radius: 8px; padding: 8px 12px; font-size: 12px; margin-bottom: 14px; }
    .err { background: #3a1c1c; border: 1px solid #5a2a2a; color: #ffd7d7; border-radius: 8px; padding: 8px 12px; font-size: 12px; margin-bottom: 14px; }
    .card { background: #171912; border: 1px solid #2a2e22; border-radius: 8px; padding: 14px; margin-bottom: 10px; }
    .ttl { font-weight: 600; }
    .meta { color: #8b91a0; font-size: 12px; margin: 2px 0 8px; }
    .detail { margin: 0 0 10px; font-size: 14px; }
    .preview { margin: 0 0 10px; }
    .preview-label { color: #8b91a0; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; margin-bottom: 5px; }
    .thumb { display: block; max-width: 320px; width: 100%; height: auto; border-radius: 8px; border: 1px solid #232733; }
    .snippet { background: #12151c; border: 1px solid #232733; border-left: 3px solid #6f5a2f; border-radius: 8px; padding: 8px 12px; margin: 0 0 10px; }
    .snippet-label { color: #8b91a0; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; margin-bottom: 4px; }
    .snippet-text { margin: 0; font-size: 14px; white-space: pre-wrap; word-break: break-word; color: #e6e8ee; }
    .csam { background: #2a1414; border: 1px solid #5a2a2a; color: #ffd7d7; border-radius: 8px; padding: 10px 12px; font-size: 13px; margin: 0 0 10px; }
    .row { display: flex; gap: 8px; }
    button { border: 0; border-radius: 8px; padding: 7px 14px; font-size: 13px; cursor: pointer; }
    .approve { background: #2f6f3e; color: #eaffea; }
    .deny { background: #6f2f2f; color: #ffeaea; }
    .empty { color: #8b91a0; }
    table.cov { width: 100%; border-collapse: collapse; font-size: 13px; }
    .cov th, .cov td { text-align: left; padding: 8px; border-bottom: 1px solid #232733; }
    .cov .how { color: #9aa0ad; }
    .protect { background: #141821; border: 1px solid #232733; border-radius: 12px; padding: 16px; margin: 0 0 18px; }
    .protect-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .protect-state { font-weight: 600; font-size: 15px; }
    .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }
    .dot-on { background: #36c75f; box-shadow: 0 0 8px #36c75f88; }
    .dot-off { background: #5a606e; }
    .connect { background: #2f6f3e; color: #eaffea; font-weight: 600; padding: 9px 20px; }
    .disconnect { background: #6f2f2f; color: #ffeaea; font-weight: 600; padding: 9px 20px; }
    button:disabled { opacity: .6; cursor: default; }
    .protect-grid { margin-top: 14px; display: grid; grid-template-columns: 1fr; gap: 6px; }
    .pg-row { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; padding: 4px 0; border-bottom: 1px solid #1c212b; }
    .pg-k { color: #8b91a0; }
    .pg-v { text-align: right; word-break: break-all; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    .ok { color: #6fe39a; }
    .off { color: #9aa0ad; }
    .mode-sel { display: flex; gap: 8px; margin-top: 14px; }
    .mode-opt { background: #12151c; color: #c8ccd6; border: 1px solid #232733; font-weight: 500; padding: 7px 14px; }
    .mode-on { background: #1f2a3a; color: #dce7ff; border-color: #3a5170; box-shadow: 0 0 0 1px #3a5170; }
    .mode-explain { margin-top: 8px; color: #9aa0ad; font-size: 12px; }
    .player { margin: 0 0 10px; }
    .player .vid { display: block; max-width: 360px; width: 100%; height: auto; border-radius: 8px; border: 1px solid #232733; background: #000; }
    .player .seg-note { color: #8b91a0; font-size: 12px; padding: 8px 0; }
    .ca-hint { margin-top: 12px; background: #12151c; border: 1px solid #232733; border-radius: 8px; padding: 10px 12px; font-size: 12px; color: #c8ccd6; }
    .ca-cmd { margin-top: 6px; padding: 8px; background: #0c0e13; border-radius: 6px; word-break: break-all; user-select: all; }

    /* Per-child VPN control row (replaces former inline styles). */
    .vpn-row { margin-top: 12px; display: flex; flex-direction: column; gap: 12px; border-top: 1px solid #232a1f; padding-top: 12px; }
    .vpn-field { display: grid; gap: 6px; margin: 0; }
    .vpn-label { color: #8b917f; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
    .vpn-seg { display: inline-flex; gap: 4px; background: #11140f; border: 1px solid #292d24; border-radius: 8px; padding: 3px; align-self: flex-start; flex-wrap: wrap; }
    .vpn-seg-btn { background: transparent; color: #aeb5a6; border: 0; border-radius: 6px; padding: 6px 12px; font-size: 13px; cursor: pointer; }
    .vpn-seg-btn:hover { color: #e8f3df; }
    .vpn-seg-on { background: #2a3b2b; color: #e8f3df; }
    .vpn-controls { display: flex; gap: 10px; align-items: end; flex-wrap: wrap; }
    .vpn-select { background: #0e100d; border: 1px solid #30362b; color: #eceee8; border-radius: 8px; padding: 8px 10px; font: inherit; min-width: 140px; }
    .vpn-toggle { border: 1px solid transparent; border-radius: 8px; padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer; }
    .vpn-toggle-on { background: #1f2b21; color: #e8f3df; border-color: #38533a; }
    .vpn-toggle-off { background: #2a1414; color: #ffd7d7; border-color: #5a2a2a; }
    .vpn-apply { padding: 8px 16px; }
    .vpn-note { color: #8b917f; font-size: 12px; margin-top: 2px; }

    /* Scannable pairing QR shown beside the typed pair code. */
    .pair-qr { margin-top: 12px; display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
    .pair-qr-img { width: 180px; height: 180px; flex: 0 0 auto; background: #eceee8; border: 1px solid #566347; border-radius: 8px; padding: 8px; box-sizing: border-box; }
    .pair-qr-img svg { display: block; width: 100%; height: 100%; }
    .pair-qr .hint { flex: 1; min-width: 180px; margin-top: 0; }

    /* Protection panel intro. */
    .protect-intro { margin-bottom: 14px; }
    .protect-intro h2 { margin-bottom: 4px; }
    .protect-intro .sub { margin-bottom: 0; }
"#;

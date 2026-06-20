//! Console CSS — a compact DARK operators dashboard (deliberately distinct from
//! the calm light guardian Manager): this is an internal ops tool, not a
//! family-facing product. Brand navy `#0F3D5C` + Sky `#3AA0DC` accents.

pub const CSS: &str = r#"
* { box-sizing: border-box; }
:root {
  --navy:#0F3D5C; --navy-deep:#0A2C44; --sky:#3AA0DC; --ink:#0b1722;
  --panel:#10222f; --panel-2:#152c3b; --line:#21384a;
  --text:#e7eef4; --dim:#9fb6c6; --good:#57A639; --warn:#d6a52a; --bad:#E5484D;
}
body, html { margin:0; }
.staff {
  min-height:100vh; background:linear-gradient(160deg,#0a1a26,#0d2433 60%,#0a1a26);
  color:var(--text); font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif;
  font-size:14px;
}
.gate { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:32px; }
.card {
  width:100%; max-width:380px; background:var(--panel); border:1px solid var(--line);
  border-radius:16px; padding:28px; box-shadow:0 20px 60px rgba(0,0,0,.4);
}
.brand { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
.brand .dot { width:12px; height:12px; border-radius:4px; background:var(--sky); }
.brand h1 { font-size:18px; margin:0; font-weight:700; letter-spacing:.2px; }
.muted { color:var(--dim); }
.sub { color:var(--dim); font-size:12.5px; margin:4px 0 20px; }
label { display:block; font-size:12px; color:var(--dim); margin:14px 0 6px; }
input {
  width:100%; padding:11px 12px; border-radius:10px; border:1px solid var(--line);
  background:var(--ink); color:var(--text); font-size:14px;
}
input:focus { outline:none; border-color:var(--sky); }
.btn {
  width:100%; margin-top:20px; padding:12px; border:none; border-radius:10px;
  background:var(--sky); color:#04121c; font-weight:700; font-size:14px; cursor:pointer;
}
.btn:disabled { opacity:.55; cursor:default; }
.btn.ghost { background:transparent; color:var(--text); border:1px solid var(--line); width:auto; padding:8px 14px; margin:0; font-weight:600; }
.err { margin-top:14px; color:#ffd7d9; background:rgba(229,72,77,.14); border:1px solid rgba(229,72,77,.4); padding:10px 12px; border-radius:10px; font-size:13px; }
.app { max-width:1100px; margin:0 auto; padding:22px; }
.topbar { display:flex; align-items:center; justify-content:space-between; padding-bottom:16px; border-bottom:1px solid var(--line); }
.topbar h1 { font-size:17px; margin:0; }
.who { display:flex; align-items:center; gap:14px; }
.pill { font-size:12px; color:var(--dim); background:var(--panel-2); border:1px solid var(--line); padding:5px 10px; border-radius:999px; }
.tabs { display:flex; gap:6px; margin:16px 0; flex-wrap:wrap; }
.tab { padding:8px 14px; border-radius:999px; border:1px solid var(--line); color:var(--dim); text-decoration:none; font-weight:600; font-size:13px; }
.tab.on { background:var(--sky); color:#04121c; border-color:var(--sky); }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:14px; }
.tile { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:16px; }
.tile .k { color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }
.tile .v { font-size:24px; font-weight:700; margin-top:6px; }
.tile .s { color:var(--dim); font-size:12px; margin-top:4px; }
.dot-i { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px; vertical-align:middle; }
.ok { color:var(--good); } .warn { color:var(--warn); } .bad { color:var(--bad); }
.bg-ok { background:var(--good); } .bg-warn { background:var(--warn); } .bg-bad { background:var(--bad); } .bg-idle { background:var(--dim); }
table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }
th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); }
th { color:var(--dim); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
td.mono, .mono { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size:12px; }
.chain { font-size:12.5px; padding:8px 12px; border-radius:10px; display:inline-block; margin-bottom:8px; }
.section-h { display:flex; align-items:center; justify-content:space-between; margin:6px 0 10px; }
.section-h h2 { font-size:15px; margin:0; }
.loading { color:var(--dim); padding:24px 0; }
"#;

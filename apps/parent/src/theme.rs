//! The console + auth-gate stylesheet — one source of truth, injected once by
//! both `router::GateLayout` (gate flow) and `router::ConsoleLayout` (console).
//!
//! Design system: a calm "family safety desk". Warm paper base, deep navy for
//! trust, sage/brand-green as the "all is well" signal, warm orange used
//! sparingly for warmth and primary calls-to-action. Display face = Fraunces
//! (harmonises with the child app), body = Plus Jakarta Sans. The gate is a
//! full-bleed atmospheric navy stage with a centred warm card; the console is a
//! bright, scannable dashboard with a per-child hero card. One orchestrated
//! entrance per surface; `prefers-reduced-motion` honoured throughout.

pub const CSS: &str = r#"
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600;9..144,700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

:root {
  /* Brand */
  --navy: #0F3D5C;
  --navy-deep: #0A2D44;
  --navy-ink: #0c2c40;
  --green: #57A639;
  --green-deep: #468A2D;
  --orange: #EE7B22;
  --orange-deep: #D8691A;

  /* Warm paper surfaces (console) */
  --paper: #F7F2EA;
  --paper-2: #FBF7F0;
  --card: #FFFFFF;
  --card-soft: #FCFAF5;
  --line: #ECE3D4;
  --line-soft: #F2EBDE;

  /* Ink */
  --ink: #1B2E3A;
  --ink-2: #46555F;
  --muted: #76838D;
  --faint: #9AA6AE;

  /* Signal tints */
  --green-tint: #EDF5E7;
  --green-line: #CFE4BE;
  --amber-tint: #FBF1DE;
  --amber-line: #F0DDB6;
  --rose-tint: #FBE9E4;
  --rose-line: #F1CBBF;
  --rose-ink: #9A3520;
  --navy-tint: #E9F0F5;

  /* Geometry */
  --r-xs: 8px;
  --r-sm: 11px;
  --r-md: 14px;
  --r-lg: 18px;
  --r-xl: 24px;

  /* Depth */
  --sh-sm: 0 1px 2px rgba(15,61,92,.06), 0 2px 8px -4px rgba(15,61,92,.12);
  --sh-md: 0 4px 14px -6px rgba(15,61,92,.18), 0 1px 0 rgba(255,255,255,.7) inset;
  --sh-lg: 0 22px 50px -28px rgba(10,45,68,.45), 0 1px 0 rgba(255,255,255,.7) inset;

  --display: 'Fraunces', Georgia, 'Times New Roman', serif;
  --body: 'Plus Jakarta Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
}

* { box-sizing: border-box; }
body { margin: 0; font-family: var(--body); background: var(--paper); color: var(--ink); -webkit-font-smoothing: antialiased; }
::selection { background: rgba(87,166,57,.25); color: var(--navy-ink); }
button:focus-visible, a:focus-visible, input[type='radio']:focus-visible, select:focus-visible {
  outline: 2px solid var(--green); outline-offset: 2px;
}

/* ======================================================================
   CONSOLE SHELL — a bright, calm dashboard.
   ====================================================================== */
.app {
  max-width: 1080px; margin: 0 auto; padding: 28px 26px 64px;
  animation: app-in .5s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes app-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

/* Topbar */
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 22px;
  padding: 18px 22px; margin-bottom: 20px;
  background: linear-gradient(135deg, var(--navy) 0%, var(--navy-deep) 100%);
  border-radius: var(--r-lg);
  box-shadow: 0 18px 40px -26px rgba(10,45,68,.6);
  position: relative; overflow: hidden;
}
.topbar::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: radial-gradient(60% 120% at 88% -10%, rgba(238,123,34,.20), transparent 60%),
              radial-gradient(50% 120% at 6% 120%, rgba(87,166,57,.18), transparent 62%);
}
.topbar-brand { display: flex; align-items: center; gap: 13px; position: relative; z-index: 1; min-width: 0; }
/* The Bulwark Shield logo (white-field JPG) sits inside a light "chip" on dark
   surfaces, so the white reads as an intentional badge rather than a box. */
.brand-logo-chip {
  flex: none; height: 40px; width: auto; display: block;
  background: #FFFFFF; border-radius: 11px; padding: 5px 9px;
  box-shadow: 0 4px 14px -6px rgba(0,0,0,.55), inset 0 0 0 1px rgba(255,255,255,.6);
}
.topbar h1 { font-family: var(--display); font-weight: 600; font-size: 20px; letter-spacing: -.01em; margin: 0; color: #F6FAFD; line-height: 1.1; }
.topbar h1 .accent { color: #F2A65A; }
.topbar .sub { color: #B7CCDC; margin: 3px 0 0; font-size: 12.5px; line-height: 1.4; max-width: 540px; }
.topbar-actions { display: flex; gap: 9px; flex: 0 0 auto; position: relative; z-index: 1; }

/* Status row — three calm tiles */
.status-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
.status-tile {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--r-md);
  padding: 14px 16px; min-width: 0; box-shadow: var(--sh-sm);
  display: flex; flex-direction: column; gap: 4px;
}
.status-k { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; }
.status-v { font-weight: 700; font-size: 16px; color: var(--ink); display: flex; align-items: center; gap: 7px; }
.status-v.ok { color: var(--green-deep); }
.status-v.warn { color: var(--orange-deep); }
.status-sub { color: var(--faint); font-size: 12px; overflow-wrap: anywhere; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.status-dot.live { background: var(--green); box-shadow: 0 0 0 3px rgba(87,166,57,.18); }
.status-dot.idle { background: var(--orange); box-shadow: 0 0 0 3px rgba(238,123,34,.16); }

/* Tabs — a soft segmented bar */
.tabs {
  display: flex; gap: 4px; flex-wrap: wrap; margin: 4px 0 20px; padding: 5px;
  background: var(--card-soft); border: 1px solid var(--line); border-radius: var(--r-md);
  box-shadow: var(--sh-sm);
}
.nav-btn {
  display: inline-flex; align-items: center; gap: 8px;
  background: transparent; color: var(--ink-2); border: 1px solid transparent;
  border-radius: var(--r-xs); padding: 9px 14px; font-size: 13.5px; font-weight: 600;
  text-decoration: none; cursor: pointer; transition: color .18s, background .18s;
}
.nav-ic { display: inline-flex; }
.nav-btn svg, .nav-ic svg { width: 16px; height: 16px; opacity: .65; }
.nav-btn:hover { color: var(--navy); background: rgba(15,61,92,.05); }
.nav-on { background: var(--navy); color: #fff; box-shadow: 0 6px 16px -8px rgba(15,61,92,.6); }
.nav-on:hover { background: var(--navy); color: #fff; }
.nav-on svg { opacity: .95; }
.banner-ic svg, .err svg { width: 17px; height: 17px; flex: none; }

/* Panels + headings */
.panel { margin: 0 0 8px; animation: panel-in .42s cubic-bezier(.2,.8,.2,1) both; }
@keyframes panel-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.panel-head { margin-bottom: 16px; }
.panel-head.split { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
h2 { font-family: var(--display); font-size: 22px; font-weight: 600; letter-spacing: -.01em; margin: 0 0 4px; color: var(--navy-ink); }
h3 { font-family: var(--display); font-size: 16px; font-weight: 600; margin: 0 0 12px; color: var(--navy-ink); }
.sub { color: var(--muted); margin: 0 0 6px; font-size: 13.5px; line-height: 1.5; max-width: 64ch; }

/* Generic card / box surfaces */
.card, .box, .status-card {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--r-md);
  padding: 18px; box-shadow: var(--sh-sm);
}
.card { margin-bottom: 14px; }

/* Buttons */
button { border: 0; border-radius: var(--r-xs); padding: 9px 16px; font-size: 13.5px; font-weight: 600; cursor: pointer; font-family: inherit; }
.primary, .approve, .connect {
  background: var(--green); color: #fff; font-weight: 700;
  box-shadow: 0 12px 22px -14px rgba(70,138,45,.9); transition: transform .12s, background .2s, box-shadow .2s;
}
.primary:hover, .approve:hover, .connect:hover { background: var(--green-deep); }
.primary:active, .approve:active, .connect:active { transform: translateY(1px); }
.ghost {
  background: var(--card); color: var(--ink-2); border: 1px solid var(--line);
  font-weight: 600; transition: border-color .18s, color .18s, background .18s; box-shadow: var(--sh-sm);
}
.ghost:hover { border-color: var(--navy); color: var(--navy); }
.danger-link { color: var(--rose-ink); }
.danger-link:hover { border-color: var(--rose-line); color: var(--rose-ink); background: var(--rose-tint); }
.deny, .disconnect { background: var(--card); color: var(--rose-ink); border: 1px solid var(--rose-line); transition: background .18s, border-color .18s; }
.deny:hover, .disconnect:hover { background: var(--rose-tint); border-color: #E4A893; }
button:disabled { opacity: .55; cursor: not-allowed; box-shadow: none; }
.small-btn { padding: 6px 12px; font-size: 12.5px; flex: 0 0 auto; }
.connect, .disconnect { padding: 10px 22px; }
.btn-ic { display: inline-flex; vertical-align: -3px; margin-right: 7px; }
.btn-ic svg { width: 15px; height: 15px; }
.topbar-actions .ghost { display: inline-flex; align-items: center; justify-content: center; }

/* Topbar action buttons sit on navy — give them a translucent look */
.topbar-actions .ghost { background: rgba(255,255,255,.10); border-color: rgba(255,255,255,.20); color: #EAF3FA; box-shadow: none; backdrop-filter: blur(4px); }
.topbar-actions .ghost:hover { background: rgba(255,255,255,.18); border-color: rgba(255,255,255,.34); color: #fff; }
.topbar-actions .danger-link { color: #FFD8CC; }
.topbar-actions .danger-link:hover { background: rgba(238,123,34,.18); border-color: rgba(255,180,150,.5); color: #fff; }

/* Inputs */
.field { display: grid; gap: 6px; margin-bottom: 12px; color: var(--ink-2); font-size: 12.5px; font-weight: 600; }
input.url, .field input {
  width: 100%; box-sizing: border-box; background: var(--card); border: 1.5px solid var(--line);
  color: var(--ink); border-radius: var(--r-sm); padding: 11px 12px; font: inherit; font-size: 14.5px; font-weight: 500;
  transition: border-color .18s, box-shadow .18s;
}
input.url:focus, .field input:focus { outline: none; border-color: var(--green); box-shadow: 0 0 0 3px rgba(87,166,57,.16); }
.hint { color: var(--muted); font-size: 12.5px; margin-top: 8px; line-height: 1.5; }

/* Banners + errors */
.banner {
  display: flex; align-items: center; gap: 10px;
  background: var(--amber-tint); border: 1px solid var(--amber-line); color: #7c5410;
  border-radius: var(--r-sm); padding: 11px 14px; font-size: 13px; margin-bottom: 16px;
}
.err {
  display: flex; align-items: flex-start; gap: 9px;
  background: var(--rose-tint); border: 1px solid var(--rose-line); color: var(--rose-ink);
  border-radius: var(--r-sm); padding: 11px 14px; font-size: 13px; margin-bottom: 14px;
}

/* URGENT child-SOS treatment: red banner + a red register on the alert card */
.sos-banner {
  display: flex; align-items: center; gap: 10px;
  background: var(--rose-tint); border: 1px solid var(--rose-line); color: var(--rose-ink);
  border-radius: var(--r-sm); padding: 12px 14px; font-size: 13.5px; font-weight: 700; margin-bottom: 16px;
}
.sos-banner svg { width: 17px; height: 17px; flex: none; }
.alert-sos { border-color: var(--rose-line); box-shadow: 0 0 0 1px var(--rose-line), var(--sh-sm); }
.alert-sos::before { background: linear-gradient(180deg, var(--rose-line), var(--rose-ink)); }
.alert-sos .alert-eyebrow { color: var(--rose-ink); }
.alert-sos .ttl { font-family: var(--display); font-size: 17px; letter-spacing: -.01em; }
.alert-ic.sos { background: var(--rose-tint); border: 1px solid var(--rose-line); color: var(--rose-ink); }
.seg-note { margin-top: 12px; color: var(--green-deep); font-size: 13px; font-weight: 600; }
.ok-note svg, .gate-info svg, .gate-error svg, .csam svg, .vpn-note svg { width: 16px; height: 16px; flex: none; margin-top: 1px; }

/* ======================================================================
   EMPTY STATES — calm, never alarming.
   ====================================================================== */
.empty-state {
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; align-items: center; text-align: center; gap: 8px;
  padding: 52px 20px 50px; border: 1.5px dashed var(--green-line); border-radius: var(--r-lg);
  background:
    radial-gradient(60% 90% at 50% 0%, rgba(87,166,57,.07), transparent 70%),
    var(--card-soft);
}
.empty-ic {
  position: relative; width: 58px; height: 58px; border-radius: 50%; display: grid; place-items: center; margin-bottom: 10px;
  background: var(--green-tint); border: 1px solid var(--green-line);
  animation: empty-float 5s ease-in-out infinite;
}
.empty-ic::before, .empty-ic::after {
  content: ""; position: absolute; inset: -14px; border-radius: 50%;
  border: 1px solid var(--green-line); opacity: .55; pointer-events: none;
}
.empty-ic::after { inset: -30px; opacity: .25; }
@keyframes empty-float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
.empty-ic svg { width: 28px; height: 28px; color: var(--green-deep); }
.empty-state .empty { margin: 6px 0 0; font-family: var(--display); font-weight: 600; font-size: 19px; color: var(--navy-ink); animation: fade-up .5s cubic-bezier(.2,.8,.2,1) both .1s; }
.empty-sub { color: var(--muted); font-size: 13.5px; max-width: 380px; margin: 0; line-height: 1.55; animation: fade-up .5s cubic-bezier(.2,.8,.2,1) both .2s; }
.empty { color: var(--muted); }

/* ======================================================================
   ALERT CARD
   ====================================================================== */
.alert-card {
  position: relative; background: var(--card); border: 1px solid var(--line); border-radius: var(--r-md);
  padding: 0 0 0 4px; margin-bottom: 14px; box-shadow: var(--sh-sm); overflow: hidden;
  animation: panel-in .4s cubic-bezier(.2,.8,.2,1) both;
}
.alert-card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
/* emotional register per family: serious-but-calm, handled, or withheld */
.alert-serious::before { background: linear-gradient(180deg, var(--orange), var(--orange-deep)); }
.alert-serious { background: linear-gradient(135deg, #FFFDF9 0%, var(--card) 55%); border-color: var(--amber-line); }
.alert-handled::before { background: var(--green-line); }
.alert-withheld::before { background: linear-gradient(180deg, var(--rose-line), var(--rose-ink)); }
.alert-eyebrow { font-size: 10.5px; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; margin-bottom: 3px; }
.alert-serious .alert-eyebrow { color: var(--orange-deep); }
.alert-handled .alert-eyebrow { color: var(--green-deep); }
.alert-withheld .alert-eyebrow { color: var(--rose-ink); }
.alert-serious .ttl { font-family: var(--display); font-size: 17px; letter-spacing: -.01em; }
.alert-top { display: flex; align-items: flex-start; gap: 14px; padding: 16px 18px 4px; }
.alert-ic { flex: none; width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; }
.alert-ic svg { width: 20px; height: 20px; }
.alert-ic.warn { background: var(--amber-tint); border: 1px solid var(--amber-line); color: var(--orange-deep); }
.alert-ic.block { background: var(--navy-tint); border: 1px solid #CBDEE9; color: var(--navy); }
.alert-ic.csam { background: var(--rose-tint); border: 1px solid var(--rose-line); color: var(--rose-ink); }
.alert-head { flex: 1; min-width: 0; }
.ttl { font-weight: 700; font-size: 15px; color: var(--ink); }
.meta { color: var(--muted); font-size: 12.5px; margin: 3px 0 0; }
.alert-body { padding: 6px 18px 16px 74px; }
.detail { margin: 0 0 12px; font-size: 14px; color: var(--ink-2); line-height: 1.5; }
.preview { margin: 0 0 12px; }
.preview-label, .snippet-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; font-weight: 700; margin-bottom: 6px; }
.thumb { display: block; max-width: 320px; width: 100%; height: auto; border-radius: var(--r-sm); border: 1px solid var(--line); }
.snippet {
  background: var(--card-soft); border: 1px solid var(--line); border-left: 3px solid var(--orange);
  border-radius: var(--r-sm); padding: 11px 14px; margin: 0 0 12px;
}
.snippet-text { margin: 0; font-size: 14px; white-space: pre-wrap; word-break: break-word; color: var(--ink); line-height: 1.5; }
.csam {
  display: flex; align-items: flex-start; gap: 9px;
  background: var(--rose-tint); border: 1px solid var(--rose-line); color: var(--rose-ink);
  border-radius: var(--r-sm); padding: 12px 14px; font-size: 13px; margin: 0 0 12px; line-height: 1.5;
}
.row { display: flex; gap: 9px; flex-wrap: wrap; }

/* Blocked-segment review player */
.player { margin: 0 0 12px; }
.player .vid { display: block; max-width: 360px; width: 100%; height: auto; border-radius: var(--r-sm); border: 1px solid var(--line); background: #000; }
.player .seg-note { color: var(--muted); font-size: 12.5px; padding: 8px 0; }

/* ======================================================================
   CHILDREN — the per-child hero card.
   ====================================================================== */
.child-card {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--r-lg);
  padding: 0; margin-bottom: 16px; box-shadow: var(--sh-md); overflow: hidden;
  animation: panel-in .42s cubic-bezier(.2,.8,.2,1) both;
  transition: transform .25s cubic-bezier(.2,.8,.2,1), box-shadow .25s;
}
.child-card:hover { transform: translateY(-2px); box-shadow: 0 14px 30px -16px rgba(10,45,68,.35), 0 1px 0 rgba(255,255,255,.7) inset; }
.child-hero {
  position: relative; display: flex; align-items: center; gap: 16px; padding: 20px;
  background:
    radial-gradient(46% 140% at 100% 0%, rgba(87,166,57,.09), transparent 70%),
    radial-gradient(30% 120% at 0% 100%, rgba(238,123,34,.05), transparent 70%),
    linear-gradient(135deg, #fff 0%, var(--card-soft) 100%);
  border-bottom: 1px solid var(--line-soft);
}
.child-avatar {
  position: relative; flex: none; width: 54px; height: 54px; border-radius: 17px; display: grid; place-items: center;
  font-family: var(--display); font-weight: 600; font-size: 24px; color: #fff;
  background: linear-gradient(150deg, #17537E 0%, var(--navy) 45%, var(--navy-deep) 100%);
  box-shadow: 0 10px 20px -10px rgba(15,61,92,.75), inset 0 1px 0 rgba(255,255,255,.25), 0 0 0 3px rgba(87,166,57,.16);
}
.child-avatar::after {
  content: ""; position: absolute; right: -2px; bottom: -2px; width: 13px; height: 13px; border-radius: 50%;
  background: var(--green); border: 2.5px solid #fff;
  animation: dot-breathe 2.4s ease-in-out infinite;
}
.child-id { flex: 1; min-width: 0; }
.child-name { font-family: var(--display); font-weight: 600; font-size: 21px; letter-spacing: -.01em; color: var(--navy-ink); line-height: 1.15; }
.child-device { color: var(--muted); font-size: 12.5px; margin-top: 3px; overflow-wrap: anywhere; }
.child-care {
  display: inline-flex; align-items: center; gap: 6px; margin-top: 8px;
  padding: 3px 10px 3px 8px; border-radius: 999px; font-size: 11.5px; font-weight: 700;
  color: var(--green-deep); background: var(--green-tint); border: 1px solid var(--green-line);
}
.child-care span { display: inline-flex; }
.child-care svg { width: 13px; height: 13px; }
.child-guardians { flex: none; text-align: right; color: var(--faint); font-size: 12px; }
.child-guardians strong { display: block; font-size: 17px; color: var(--ink-2); font-family: var(--display); }

/* Per-child controls (region / strictness / on-off / apply) */
.vpn-row { display: flex; flex-direction: column; gap: 16px; padding: 18px 20px; }
.vpn-field { display: grid; gap: 8px; margin: 0; }
.vpn-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .07em; font-weight: 700; }
.vpn-seg { display: inline-flex; gap: 4px; background: var(--card-soft); border: 1px solid var(--line); border-radius: var(--r-sm); padding: 4px; align-self: flex-start; flex-wrap: wrap; }
.vpn-seg-btn { background: transparent; color: var(--ink-2); border: 0; border-radius: var(--r-xs); padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer; transition: background .18s, color .18s; }
.vpn-seg-btn:hover { color: var(--navy); background: rgba(15,61,92,.05); }
.vpn-seg-on { background: var(--navy); color: #fff; box-shadow: 0 6px 14px -8px rgba(15,61,92,.6); }
.vpn-seg-on:hover { color: #fff; background: var(--navy); }
.vpn-controls { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.vpn-select {
  appearance: none; -webkit-appearance: none;
  background: var(--card) url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'><path d='M1 1.5l5 5 5-5' fill='none' stroke='%2346555F' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>") no-repeat right 12px center;
  border: 1.5px solid var(--line); color: var(--ink); border-radius: var(--r-sm);
  padding: 10px 34px 10px 12px; font: inherit; font-size: 14px; font-weight: 500; min-width: 150px;
  cursor: pointer; transition: border-color .18s, box-shadow .18s;
}
.vpn-select:focus { outline: none; border-color: var(--green); box-shadow: 0 0 0 3px rgba(87,166,57,.16); }

/* The protection toggle is the hero control of the card */
.vpn-toggle {
  display: inline-flex; align-items: center; gap: 10px;
  border: 1.5px solid transparent; border-radius: 999px; padding: 9px 9px 9px 16px;
  font-size: 13.5px; font-weight: 700; cursor: pointer; transition: background .2s, color .2s, border-color .2s;
}
.vpn-toggle .knob { width: 36px; height: 22px; border-radius: 999px; position: relative; transition: background .2s; flex: none; }
.vpn-toggle .knob::after { content: ""; position: absolute; top: 3px; width: 16px; height: 16px; border-radius: 50%; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,.25); transition: left .2s cubic-bezier(.2,.8,.2,1); }
.vpn-toggle-on { background: var(--green-tint); color: var(--green-deep); border-color: var(--green-line); }
.vpn-toggle-on .knob { background: var(--green); }
.vpn-toggle-on .knob::after { left: 17px; }
.vpn-toggle-off { background: var(--card-soft); color: var(--muted); border-color: var(--line); }
.vpn-toggle-off .knob { background: #C7CDD2; }
.vpn-toggle-off .knob::after { left: 3px; }
.vpn-apply { padding: 10px 18px; margin-left: auto; }
.vpn-note {
  display: inline-flex; align-items: center; gap: 8px; align-self: flex-start;
  color: var(--ink-2); font-size: 13px; font-weight: 600;
  background: var(--green-tint); border: 1px solid var(--green-line); border-radius: var(--r-sm); padding: 9px 13px;
}
.vpn-note.pending { color: #7c5410; background: var(--amber-tint); border-color: var(--amber-line); }
.vpn-note.failed { color: var(--rose-ink); background: var(--rose-tint); border-color: var(--rose-line); }
.vpn-hint {
  display: flex; align-items: flex-start; gap: 8px; padding: 10px 12px; max-width: 640px;
  background: var(--navy-tint); border: 1px solid #CBDEE9; border-radius: var(--r-sm);
  color: var(--navy-ink); font-size: 12.5px; line-height: 1.45;
  margin-top: -6px; animation: fade-up .35s cubic-bezier(.2,.8,.2,1) both;
}
.vpn-hint svg { width: 15px; height: 15px; flex: none; margin-top: 1px; color: var(--navy); }

/* ======================================================================
   PROTECTION PANEL (this device)
   ====================================================================== */
.protect {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--r-lg);
  padding: 22px; box-shadow: var(--sh-md);
  animation: panel-in .42s cubic-bezier(.2,.8,.2,1) both;
}
.protect-intro { margin-bottom: 18px; }
.protect-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; padding: 16px 18px; border-radius: var(--r-md); background: var(--card-soft); border: 1px solid var(--line-soft); }
.protect-state-wrap { display: flex; align-items: center; gap: 12px; }
.protect-state { font-family: var(--display); font-weight: 600; font-size: 18px; color: var(--navy-ink); }
.dot { display: inline-grid; place-items: center; width: 34px; height: 34px; border-radius: 50%; flex: none; }
.dot-on { background: var(--green-tint); border: 1px solid var(--green-line); }
.dot-off { background: var(--card); border: 1px solid var(--line); }
.dot-on::after { content: ""; width: 12px; height: 12px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px rgba(87,166,57,.2); animation: dot-breathe 2.4s ease-in-out infinite; }
.dot-off::after { content: ""; width: 12px; height: 12px; border-radius: 50%; background: #C2C9CE; }
@keyframes dot-breathe { 0%,100% { box-shadow: 0 0 0 3px rgba(87,166,57,.18); } 50% { box-shadow: 0 0 0 7px rgba(87,166,57,.05); } }

.mode-sel { display: flex; gap: 9px; margin-top: 18px; flex-wrap: wrap; }
.mode-opt { background: var(--card); color: var(--ink-2); border: 1.5px solid var(--line); font-weight: 600; padding: 9px 16px; transition: border-color .18s, color .18s; }
.mode-opt:hover:not(:disabled) { border-color: var(--navy); color: var(--navy); }
.mode-on { background: var(--navy-tint); color: var(--navy); border-color: #BCD5E4; box-shadow: 0 0 0 1px #BCD5E4; }
.mode-explain { margin-top: 10px; color: var(--muted); font-size: 12.5px; line-height: 1.5; }

.protect-grid { margin-top: 18px; display: grid; grid-template-columns: 1fr; gap: 0; border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.pg-row { display: flex; justify-content: space-between; gap: 14px; font-size: 13.5px; padding: 12px 16px; background: var(--card); }
.pg-row:nth-child(even) { background: var(--card-soft); }
.pg-row + .pg-row { border-top: 1px solid var(--line-soft); }
.pg-k { color: var(--muted); font-weight: 600; }
.pg-v { text-align: right; word-break: break-all; font-weight: 600; color: var(--ink); }
.ok { color: var(--green-deep); }
.off { color: var(--faint); }

.ca-hint { margin-top: 16px; background: var(--navy-tint); border: 1px solid #CBDEE9; border-radius: var(--r-md); padding: 14px 16px; font-size: 13px; color: var(--navy-ink); line-height: 1.55; }
.ca-cmd { margin-top: 8px; padding: 10px 12px; background: var(--navy); color: #DCEAF3; border-radius: var(--r-xs); word-break: break-all; user-select: all; }

/* ======================================================================
   SERVER SETTINGS
   ====================================================================== */
.server-list { display: grid; gap: 10px; margin-bottom: 14px; }
.server-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; border: 1.5px solid var(--line); border-radius: var(--r-md); padding: 15px 16px; background: var(--card); transition: border-color .18s, background .18s; }
.server-row:hover { border-color: #D7CBB6; }
.server-active { border-color: var(--green-line); background: var(--green-tint); box-shadow: 0 0 0 1px var(--green-line); }
.server-main { display: flex; align-items: flex-start; gap: 12px; flex: 1; min-width: 0; margin: 0; cursor: pointer; }
.server-main input { margin-top: 4px; flex: 0 0 auto; accent-color: var(--green); width: 17px; height: 17px; }
.server-badges { display: flex; gap: 7px; flex-wrap: wrap; margin-top: 8px; }
.badge { display: inline-flex; align-items: center; gap: 5px; border: 1px solid var(--line); color: var(--muted); border-radius: 999px; padding: 3px 10px; font-size: 11.5px; font-weight: 600; background: var(--card-soft); }
.badge-ok { border-color: var(--green-line); color: var(--green-deep); background: var(--green-tint); }
.badge-warn { border-color: var(--amber-line); color: #7c5410; background: var(--amber-tint); }
.add-server { margin-top: 16px; }

/* ======================================================================
   PAIRING (add a child)
   ====================================================================== */
.add-child { margin-top: 18px; }
.pair-code { margin-top: 16px; background: var(--navy-tint); border: 1px solid #CBDEE9; border-radius: var(--r-md); padding: 18px; text-align: center; }
.code { font-family: var(--display); color: var(--navy); font-size: 38px; font-weight: 600; letter-spacing: .14em; margin: 6px 0 4px; }
.ok-note {
  display: flex; align-items: flex-start; gap: 9px;
  background: var(--green-tint); border: 1px solid var(--green-line); color: var(--green-deep);
  border-radius: var(--r-sm); padding: 11px 14px; font-size: 13px; margin-top: 14px; font-weight: 600;
}
.pair-qr { margin-top: 16px; display: flex; gap: 18px; align-items: center; flex-wrap: wrap; justify-content: center; }
.pair-qr-img { width: 184px; height: 184px; flex: 0 0 auto; background: #fff; border: 1px solid var(--line); border-radius: var(--r-md); padding: 10px; box-sizing: border-box; box-shadow: var(--sh-sm); }
.pair-qr-img svg { display: block; width: 100%; height: 100%; }
.pair-qr .hint { flex: 1; min-width: 200px; margin-top: 0; text-align: left; }

/* Setup-code handoff: segmented short code, denser v2 QR, copy action */
.code-seg { display: flex; gap: 9px; justify-content: center; flex-wrap: wrap; margin: 6px 0 4px; }
.code-seg span {
  font-family: var(--display); color: var(--navy); font-size: 32px; font-weight: 600;
  letter-spacing: .12em; background: #fff; border: 1px solid #CBDEE9; border-radius: var(--r-sm);
  padding: 6px 14px;
}
.setup-qr-img { width: 228px; height: 228px; }
.setup-row { display: flex; justify-content: center; margin-top: 14px; }
.setup-row .copy-btn { margin: 0; }

/* ======================================================================
   COVERAGE MATRIX
   ====================================================================== */
table.cov { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13.5px; border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.cov thead th { background: var(--navy); color: #DCEAF3; text-align: left; padding: 12px 14px; font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; font-weight: 700; }
.cov td { text-align: left; padding: 13px 14px; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
.cov tbody tr:last-child td { border-bottom: 0; }
.cov tbody tr:nth-child(even) td { background: var(--card-soft); }
.cov td:first-child { font-weight: 700; color: var(--ink); }
.cov-status { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; }
.cov-status::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--green); flex: none; }
.cov-status.partial::before { background: var(--orange); }
.cov .how { color: var(--muted); }

.mono { font-family: ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace; font-size: 12px; }

/* ======================================================================
   AUTH GATE — full-bleed atmospheric navy stage + centred warm card.
   ====================================================================== */
.gate-stage {
  position: relative; min-height: 100vh; box-sizing: border-box;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 20px; padding: 44px 20px 52px;
  background:
    radial-gradient(120% 90% at 78% 108%, rgba(87,166,57,.14), transparent 55%),
    radial-gradient(135% 100% at 50% -15%, #18557C 0%, var(--navy) 40%, var(--navy-deep) 100%);
  font-family: var(--body); color: var(--navy-ink); overflow: hidden;
}
/* atmosphere: a slow-breathing warm + sage aurora over the navy stage */
.gate-aurora {
  position: fixed; inset: -28% -12% auto -12%; height: 64vh; z-index: 0; pointer-events: none;
  background:
    radial-gradient(38% 52% at 20% 16%, rgba(238,123,34,.28), transparent 70%),
    radial-gradient(44% 54% at 84% 6%, rgba(87,166,57,.26), transparent 70%),
    radial-gradient(30% 44% at 55% 30%, rgba(58,160,220,.12), transparent 70%);
  filter: blur(14px);
  animation: aurora-drift 16s ease-in-out infinite;
}
@keyframes aurora-drift {
  0%, 100% { transform: translate3d(0, 0, 0) scale(1); }
  50% { transform: translate3d(2.5%, 2%, 0) scale(1.05); }
}
.gate-stage::before {
  content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none; opacity: .5;
  background-image: linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size: 38px 38px;
  mask-image: radial-gradient(80% 60% at 50% 30%, #000 0%, transparent 80%);
}
/* film grain so the navy reads as material, not flat colour */
.gate-stage::after {
  content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none; opacity: .07;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/><feColorMatrix type='saturate' values='0'/></filter><rect width='160' height='160' filter='url(%23n)'/></svg>");
}
/* one orchestrated entrance: brand settles, the card rises, the footer follows */
.gate-brand { position: relative; z-index: 1; display: flex; align-items: center; gap: 11px; color: #EAF3FB; font-weight: 700; font-size: 16px; letter-spacing: .01em; animation: fade-down .55s cubic-bezier(.2,.8,.2,1) both; }
@keyframes fade-down { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.gate-brand .brand-logo-chip { height: 34px; }
.gate-wordmark { font-family: var(--display); font-weight: 600; font-size: 16px; color: #CFE0EE; letter-spacing: .04em; text-transform: uppercase; }

.gate-card {
  position: relative; z-index: 1; width: 100%; max-width: 440px; box-sizing: border-box;
  background: var(--paper-2); border: 1px solid #EFE6D7; border-radius: var(--r-xl);
  padding: 34px 30px 30px; box-shadow: var(--sh-lg);
  animation: gate-rise .6s cubic-bezier(.2,.8,.2,1) both; animation-delay: .12s;
}
@keyframes gate-rise { from { opacity: 0; transform: translateY(18px) scale(.985); } to { opacity: 1; transform: translateY(0) scale(1); } }
.gate-foot { position: relative; z-index: 1; max-width: 440px; text-align: center; color: #A7C2D5; font-size: 12px; line-height: 1.55; margin: 0; animation: fade-up .6s cubic-bezier(.2,.8,.2,1) both; animation-delay: .55s; }

/* Hero glyph (shield SVG) */
.gate-hero {
  width: 76px; height: 86px; margin: 0 auto 16px; position: relative;
  clip-path: polygon(50% 0, 100% 16%, 100% 56%, 50% 100%, 0 56%, 0 16%);
  background: linear-gradient(165deg, var(--green) 0%, #3F7A2A 100%);
  display: grid; place-items: center;
  box-shadow: 0 18px 34px -16px rgba(70,138,45,.7);
}
.gate-hero svg { width: 34px; height: 34px; color: #fff; }
.gate-hero.locked { background: linear-gradient(165deg, var(--navy) 0%, var(--navy-deep) 100%); box-shadow: 0 18px 34px -16px rgba(15,61,92,.7); }

/* The real Bulwark Shield logo as the brand hero on the light card. The JPG is
   on a white field, so `multiply` blends it into the warm paper (white drops
   out) — no white box, the mark + wordmark read cleanly. */
.gate-hero-logo {
  display: block; width: 152px; height: auto; margin: 0 auto 16px;
  mix-blend-mode: multiply;
  animation: gate-rise .6s cubic-bezier(.2,.8,.2,1) both;
}
.gate-splash .gate-hero-logo { width: 172px; margin-bottom: 22px; }

.gate-title { font-family: var(--display); font-size: 28px; line-height: 1.12; letter-spacing: -.01em; color: var(--navy-ink); font-weight: 600; margin: 0 0 10px; text-align: center; animation: fade-up .55s cubic-bezier(.2,.8,.2,1) both; animation-delay: .22s; }
.gate-title em { font-style: italic; color: var(--orange); }
.gate-lede { font-size: 15px; line-height: 1.58; color: var(--ink-2); margin: 0 0 22px; text-align: center; animation: fade-up .55s cubic-bezier(.2,.8,.2,1) both; animation-delay: .3s; }

/* what-it-does facts (staggered entrance, after the headline has landed) */
.gate-facts { list-style: none; padding: 0; margin: 0 0 20px; display: flex; flex-direction: column; gap: 11px; }
.gate-fact { display: flex; gap: 13px; align-items: center; padding: 14px 15px; border-radius: var(--r-md); background: var(--card-soft); border: 1px solid var(--line); animation: fade-up .5s cubic-bezier(.2,.8,.2,1) both; animation-delay: calc(var(--i, 0) * 90ms + 380ms); }
@keyframes fade-up { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.gf-ic { flex: none; width: 38px; height: 38px; border-radius: 11px; background: var(--green-tint); border: 1px solid var(--green-line); display: grid; place-items: center; color: var(--green-deep); }
.gf-ic svg { width: 19px; height: 19px; }
.gate-fact strong { display: block; font-size: 14.5px; color: var(--navy-ink); margin-bottom: 2px; font-weight: 700; }
.gate-fact span { display: block; font-size: 13px; color: var(--muted); line-height: 1.5; }

.gate-privacy { display: flex; gap: 11px; align-items: flex-start; padding: 13px 15px; border-radius: var(--r-md); background: var(--green-tint); border: 1px solid var(--green-line); margin-bottom: 22px; animation: fade-up .5s cubic-bezier(.2,.8,.2,1) both; animation-delay: .62s; }
.gp-ic { flex: none; color: var(--green-deep); }
.gp-ic svg { width: 20px; height: 20px; }
.gate-privacy span:last-child { font-size: 13px; color: #3a5b2c; line-height: 1.55; }

/* buttons */
.gate-primary {
  width: 100%; border: 0; background: var(--green); color: #fff; font-family: inherit;
  font-weight: 700; font-size: 15.5px; padding: 15px 18px; border-radius: var(--r-md); cursor: pointer;
  box-shadow: 0 16px 28px -14px rgba(70,138,45,.85); transition: transform .12s, background .2s, box-shadow .2s; margin-bottom: 9px;
}
.gate-primary:hover { background: var(--green-deep); }
.gate-primary:active { transform: translateY(1px); }
.gate-primary:disabled { background: #C9D8BF; color: #F2F7EE; box-shadow: none; cursor: not-allowed; }
.gate-ghost { width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; border: 0; background: transparent; color: var(--ink-2); font-family: inherit; font-weight: 600; font-size: 14.5px; padding: 12px; border-radius: var(--r-md); cursor: pointer; transition: color .18s; }
.gate-ghost .gg-ic svg, .gate-ghost svg { width: 15px; height: 15px; flex: none; }
.gate-ghost:hover { color: var(--navy); }
.gate-ghost.danger-link { color: #A2452F; background: transparent; border: 0; }
.gate-ghost.danger-link:hover { color: #82371F; }

/* fields */
.gate-field { display: flex; flex-direction: column; gap: 7px; margin-bottom: 15px; }
.gate-field label { font-size: 12.5px; font-weight: 700; color: var(--ink-2); }
.gate-field input {
  width: 100%; box-sizing: border-box; background: #fff; border: 1.5px solid #E3D9C9; color: var(--navy-ink);
  border-radius: var(--r-sm); padding: 13px 14px; font: inherit; font-size: 15px; font-weight: 500; transition: border-color .18s, box-shadow .18s;
}
.gate-field input:focus { outline: none; border-color: var(--green); box-shadow: 0 0 0 3px rgba(87,166,57,.18); }
.gate-field input::placeholder { color: #B6AB98; }
.gate-hint-bad { font-size: 12px; color: #A2452F; font-weight: 600; }

/* segmented Create / Sign in */
.gate-seg { display: flex; gap: 4px; background: #F0EADF; border: 1px solid #E6DCCC; border-radius: var(--r-md); padding: 4px; margin-bottom: 18px; }
.gate-seg-btn { flex: 1; border: 0; background: transparent; color: var(--muted); font-family: inherit; font-weight: 700; font-size: 14px; padding: 10px; border-radius: var(--r-xs); cursor: pointer; transition: background .18s, color .18s; }
.gate-seg-on { background: #fff; color: var(--navy); box-shadow: 0 3px 8px -4px rgba(15,61,92,.35); }

.gate-info { display: flex; align-items: flex-start; gap: 9px; font-size: 13px; color: var(--navy-ink); background: var(--amber-tint); border: 1px solid var(--amber-line); border-radius: var(--r-sm); padding: 11px 13px; margin-bottom: 15px; line-height: 1.5; }
.gate-error { display: flex; align-items: flex-start; gap: 9px; font-size: 13px; color: var(--rose-ink); background: var(--rose-tint); border: 1px solid var(--rose-line); border-radius: var(--r-sm); padding: 11px 13px; margin-bottom: 13px; line-height: 1.5; }
.gate-fine { font-size: 12px; color: var(--faint); text-align: center; margin: 13px 0 0; line-height: 1.55; }

/* Self-service auth: forgot-password link, recovery-code display, copy button */
.gate-link { background: none; border: none; color: var(--green-deep); font-size: 13px; font-weight: 600; cursor: pointer; padding: 6px 4px; margin: 2px auto 0; display: block; text-decoration: underline; text-underline-offset: 3px; }
.gate-link:hover { color: var(--green); }
.recovery-code {
  font-family: ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
  font-size: 19px; font-weight: 600; letter-spacing: .06em; color: var(--navy-ink);
  background: linear-gradient(180deg, #FFFDF8, var(--card-soft));
  border: 1.5px dashed var(--green-line); border-radius: var(--r-md);
  padding: 16px 14px; margin: 4px 0 12px; text-align: center; word-break: break-all;
  user-select: all; -webkit-user-select: all;
}
.copy-btn { display: inline-flex; align-items: center; gap: 8px; margin: 0 auto 14px; }
.copy-btn svg { width: 16px; height: 16px; }
.ok-banner { display: flex; align-items: center; gap: 10px; font-size: 14px; color: var(--green-deep); background: var(--green-tint); border: 1px solid var(--green-line); border-radius: var(--r-sm); padding: 13px 15px; margin-bottom: 16px; line-height: 1.5; font-weight: 600; }
.ok-banner svg { width: 18px; height: 18px; flex: none; }
.panel-narrow { max-width: 460px; }

.gate-or { display: flex; align-items: center; gap: 12px; margin: 8px 0 16px; color: var(--faint); font-size: 12px; font-weight: 600; }
.gate-or::before, .gate-or::after { content: ""; flex: 1; height: 1px; background: #E6DCCC; }

/* password strength */
.pw-strength { display: flex; align-items: center; gap: 10px; margin-top: 4px; }
.pw-bar { flex: 1; height: 7px; border-radius: 999px; background: #EAE1D2; overflow: hidden; }
.pw-fill { height: 100%; border-radius: 999px; transition: width .25s ease, background .25s ease; }
.pw-fill.ps-weak { background: var(--orange); }
.pw-fill.ps-ok { background: var(--green); }
.pw-fill.ps-strong { background: var(--green-deep); }
.pw-label { font-size: 12px; font-weight: 700; }
.pw-label.ps-weak { color: var(--orange-deep); }
.pw-label.ps-ok { color: var(--green-deep); }
.pw-label.ps-strong { color: var(--green-deep); }

/* region picker */
.region-list { display: flex; flex-direction: column; gap: 10px; margin-bottom: 18px; }
.region-row {
  display: flex; align-items: center; gap: 14px; width: 100%; text-align: left;
  background: var(--card-soft); border: 1.5px solid var(--line); border-radius: var(--r-md); padding: 14px 15px;
  font-family: inherit; cursor: pointer; transition: border-color .18s, background .18s, box-shadow .18s;
  animation: fade-up .5s cubic-bezier(.2,.8,.2,1) both; animation-delay: calc(var(--i, 0) * 70ms + 380ms);
}
.region-row:hover { border-color: #D2C4AE; }
.region-on { border-color: var(--green-line); background: var(--green-tint); box-shadow: 0 0 0 2px rgba(87,166,57,.16); }
.region-flag { flex: none; width: 40px; height: 40px; border-radius: 11px; background: #fff; border: 1px solid var(--line); display: grid; place-items: center; }
.region-flag svg { width: 22px; height: 22px; color: var(--navy); }
.region-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.region-name { font-size: 14.5px; font-weight: 700; color: var(--navy-ink); }
.region-meta { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
.region-check { flex: none; width: 26px; height: 26px; border-radius: 50%; background: var(--green); color: #fff; display: grid; place-items: center; }
.region-check svg { width: 14px; height: 14px; }
.region-self { border-style: dashed; }

/* splash — the shield breathes while a soft sweep marks the wait */
.gate-splash { display: flex; flex-direction: column; align-items: center; gap: 16px; padding: 28px 0; }
.gate-splash .gate-hero { animation: gate-pulse 1.7s ease-in-out infinite; }
.gate-splash .gate-hero-logo { animation: gate-pulse 2.4s ease-in-out infinite; }
.gate-splash::after {
  content: ""; width: 132px; height: 4px; border-radius: 999px;
  background-color: rgba(15,61,92,.10);
  background-image: linear-gradient(90deg, transparent, rgba(87,166,57,.8), transparent);
  background-size: 45% 100%; background-repeat: no-repeat;
  animation: splash-sweep 1.5s ease-in-out infinite;
}
@keyframes splash-sweep { 0% { background-position: -90% 0; } 100% { background-position: 190% 0; } }
@keyframes gate-pulse { 0%,100% { transform: scale(1); opacity: .92; } 50% { transform: scale(1.06); opacity: 1; } }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}

@media (max-width: 720px) {
  .status-grid { grid-template-columns: 1fr; }
  .topbar { flex-direction: column; align-items: flex-start; }
  .topbar-actions { width: 100%; }
  .topbar-actions .ghost { flex: 1; }
}
@media (max-width: 480px) {
  .gate-card { padding: 28px 22px 26px; border-radius: var(--r-lg); }
  .gate-title { font-size: 25px; }
  .app { padding: 18px 16px 48px; }
  .vpn-apply { margin-left: 0; }
  .alert-body { padding: 6px 16px 16px; }
}
"#;

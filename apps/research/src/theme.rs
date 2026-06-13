//! The single source-of-truth stylesheet, injected once by `app::App`.
//!
//! DESIGN LANGUAGE — "vigilant frontier lab". Two brand inputs are synthesised:
//! the gritty Predator Hunters identity (red-on-black, serious, since 2017) and
//! the Bulwark Shield mark (lime-green + orange figures on navy). Result:
//!   * a deep navy-black stage,
//!   * an ember RED→ORANGE signature gradient (Predator Hunters intensity — used
//!     for headlines, primary actions, brand moments),
//!   * lime-GREEN reserved as the "protected / active" signal (the protective
//!     tech — status dots, capability icons, telemetry).
//! "We fight (ember) to protect (green)."
//!
//! Display = Fraunces (optical serif, investigative gravity); UI/body = Hanken
//! Grotesk; technical labels / telemetry = Spline Sans Mono.
//!
//! LIGHT + DARK: every theme-dependent colour is a CSS variable on `:root`
//! (dark default) and overridden under `.theme-root[data-theme="light"]`, so
//! the whole site recolours from one attribute toggled by the nav switch.
//! Atmosphere is layered (aurora + engineering grid + grain + vignette);
//! scroll-driven reveals via `animation-timeline: view()`; reduced-motion honoured.

pub const STYLE: &str = r#"
@import url('https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400;0,9..144,500;0,9..144,600;1,9..144,400;1,9..144,500&family=Hanken+Grotesk:wght@400;500;600;700&family=Spline+Sans+Mono:wght@400;500;600&display=swap');

:root {
  /* Stage (dark default) */
  --bg:        #08111B;
  --bg-2:      #0B1622;
  --head:      #F4F8FA;
  --ink:       #E6EEF4;
  --ink-2:     #A6BAC8;
  --muted:     #6C8192;
  --faint:     #45576A;
  --hair:        rgba(176,205,224,.10);
  --hair-strong: rgba(176,205,224,.20);

  /* Surfaces (variable so light mode can repaint them) */
  --nav-bg:     rgba(10,18,30,.62);
  --pill-bg:    rgba(10,18,30,.5);
  --card-bg:    linear-gradient(180deg, rgba(19,38,55,.5), rgba(10,18,30,.5));
  --readout-bg: linear-gradient(180deg, rgba(19,38,55,.85), rgba(10,18,30,.85));
  --cta-bg:     linear-gradient(180deg, rgba(17,33,48,.7), rgba(9,15,24,.7));
  --member-bg:  rgba(14,28,42,.5);
  --grain-op:   .05;
  --vignette:   rgba(0,0,0,.55);

  /* Brand accents */
  --red:    #ED2A33;   /* Predator Hunters red */
  --orange: #F58220;   /* Bulwark orange figure */
  --green:  #8FD24A;   /* Bulwark green figure — protected / alive */
  --green-2:#5FA32E;
  --sky:    #6FA8D0;   /* cool tertiary — "research" status only */
  --navy:   #0F3D5C;

  /* Signature ember gradient = red → orange */
  --grad:      linear-gradient(98deg, #ED2A33 0%, #F2592A 48%, #F58220 100%);
  --grad-soft: linear-gradient(98deg, rgba(237,42,51,.16), rgba(245,130,32,.16));
  --on-grad:   #FFFFFF;          /* text on the ember gradient */
  --green-glow: rgba(143,210,74,1);

  /* Geometry */
  --r-sm: 10px; --r-md: 14px; --r-lg: 20px; --r-xl: 28px;
  --maxw: 1200px;
  --gut: clamp(20px, 5vw, 64px);

  --display: 'Fraunces', Georgia, 'Times New Roman', serif;
  --sans: 'Hanken Grotesk', system-ui, -apple-system, 'Segoe UI', sans-serif;
  --mono: 'Spline Sans Mono', ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
}

/* ------- LIGHT MODE ------- */
.theme-root[data-theme="light"] {
  --bg:        #EEF2F6;
  --bg-2:      #FFFFFF;
  --head:      #0C1A28;
  --ink:       #16242F;
  --ink-2:     #46586A;
  --muted:     #6B7C8A;
  --faint:     #9AA8B4;
  --hair:        rgba(18,40,60,.12);
  --hair-strong: rgba(18,40,60,.20);

  --nav-bg:     rgba(255,255,255,.74);
  --pill-bg:    rgba(255,255,255,.7);
  --card-bg:    linear-gradient(180deg, #FFFFFF, #F5F8FB);
  --readout-bg: linear-gradient(180deg, #FFFFFF, #F2F6FB);
  --cta-bg:     linear-gradient(180deg, #FFFFFF, #F1F6FA);
  --member-bg:  #FFFFFF;
  --grain-op:   .025;
  --vignette:   rgba(15,40,65,.10);
  --green-2:    #4E8C24;
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; background: #08111B; }
body { margin: 0; }
.theme-root {
  min-height: 100dvh; background: var(--bg); color: var(--ink);
  font-family: var(--sans); font-size: 17px; line-height: 1.7;
  -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  overflow-x: hidden; transition: background .4s ease, color .4s ease;
}
::selection { background: rgba(245,130,32,.28); color: #FFF3E8; }
a { color: inherit; text-decoration: none; }
:focus-visible { outline: 2px solid var(--orange); outline-offset: 3px; border-radius: 4px; }
img { max-width: 100%; display: block; }

/* ===================================================================
   ATMOSPHERE — fixed, behind everything.
   =================================================================== */
.stage-bg { position: fixed; inset: 0; z-index: -2; pointer-events: none; overflow: hidden; }
.stage-bg::before {
  content: ""; position: absolute; inset: -20%;
  background:
    radial-gradient(38% 44% at 16% 8%,  rgba(245,130,32,.18), transparent 62%),
    radial-gradient(34% 38% at 88% 4%,  rgba(237,42,51,.14),  transparent 60%),
    radial-gradient(50% 50% at 74% 98%, rgba(143,210,74,.12), transparent 66%);
  filter: blur(30px);
  animation: aurora 22s ease-in-out infinite;
}
.theme-root[data-theme="light"] .stage-bg::before { opacity: .55; }
@keyframes aurora {
  0%,100% { transform: translate3d(0,0,0) scale(1); }
  50%     { transform: translate3d(-2.4%, 1.8%, 0) scale(1.06); }
}
.stage-grid { position: fixed; inset: 0; z-index: -2; pointer-events: none; opacity: .5;
  background-image:
    linear-gradient(var(--hair) 1px, transparent 1px),
    linear-gradient(90deg, var(--hair) 1px, transparent 1px);
  background-size: 64px 64px;
  -webkit-mask-image: radial-gradient(120% 80% at 50% 0%, #000 0%, transparent 78%);
          mask-image: radial-gradient(120% 80% at 50% 0%, #000 0%, transparent 78%);
}
.stage-grain { position: fixed; inset: 0; z-index: -1; pointer-events: none; opacity: var(--grain-op); mix-blend-mode: overlay;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='180' height='180'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' stitchTiles='stitch'/><feColorMatrix type='saturate' values='0'/></filter><rect width='180' height='180' filter='url(%23n)'/></svg>"); }
.theme-root::after { content: ""; position: fixed; inset: 0; z-index: -1; pointer-events: none;
  background: radial-gradient(130% 100% at 50% 30%, transparent 56%, var(--vignette) 100%); }

/* ===================================================================
   LAYOUT
   =================================================================== */
.wrap { width: 100%; max-width: var(--maxw); margin: 0 auto; padding: 0 var(--gut); }
.section { padding: clamp(72px, 11vh, 150px) 0; position: relative; }
.section + .section { border-top: 1px solid var(--hair); }

.sec-head { display: grid; grid-template-columns: minmax(0,1fr); gap: 18px; margin-bottom: clamp(32px,5vw,60px); }
.sec-index { font-family: var(--mono); font-size: .76rem; letter-spacing: .26em; text-transform: uppercase;
  color: var(--green-2); display: inline-flex; align-items: center; gap: 12px; }
.sec-index::before { content: ""; width: 30px; height: 1px; background: linear-gradient(90deg, var(--green), transparent); }
.eyebrow { font-family: var(--mono); font-size: .74rem; letter-spacing: .26em; text-transform: uppercase; color: var(--green-2); }

h1, h2, h3 { font-family: var(--display); font-weight: 400; font-optical-sizing: auto; letter-spacing: -.018em; margin: 0; color: var(--head); }
h2 { font-size: clamp(1.95rem, 3.6vw, 3.05rem); line-height: 1.08; }
h3 { font-size: clamp(1.2rem, 1.7vw, 1.5rem); line-height: 1.18; letter-spacing: -.012em; }
.lede { font-size: clamp(1.06rem, 1.5vw, 1.34rem); line-height: 1.6; color: var(--ink-2); max-width: 60ch; font-weight: 400; }
p { color: var(--ink-2); }
.grad-text { background: var(--grad); -webkit-background-clip: text; background-clip: text; color: transparent; }
em.em { font-style: italic; color: var(--head); }

/* ===================================================================
   NAV
   =================================================================== */
.nav { position: sticky; top: 0; z-index: 40; }
.nav-inner { display: flex; align-items: center; justify-content: space-between; gap: 18px;
  margin: 14px auto; padding: 10px 12px 10px 18px; max-width: var(--maxw);
  width: calc(100% - 2*var(--gut));
  background: var(--nav-bg); border: 1px solid var(--hair); border-radius: 999px;
  backdrop-filter: blur(16px) saturate(140%); -webkit-backdrop-filter: blur(16px) saturate(140%);
  box-shadow: 0 18px 40px -28px rgba(0,0,0,.9); }
.brand { display: inline-flex; align-items: center; gap: 11px; min-width: 0; }
.brand-glyph { width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center; flex: none;
  background: var(--grad-soft); border: 1px solid var(--hair-strong); color: var(--orange);
  box-shadow: inset 0 0 18px -8px var(--orange); }
.brand-glyph svg { width: 17px; height: 17px; }
.brand-name { display: flex; flex-direction: column; line-height: 1; }
.brand-name b { font-family: var(--sans); font-weight: 700; font-size: .98rem; letter-spacing: .01em; color: var(--head); }
.brand-name span { font-family: var(--mono); font-size: .6rem; letter-spacing: .34em; text-transform: uppercase; color: var(--muted); margin-top: 4px; }
.nav-links { display: flex; align-items: center; gap: 4px; }
.nav-link { font-size: .92rem; color: var(--ink-2); padding: 9px 14px; border-radius: 999px; transition: color .18s, background .18s; }
.nav-link:hover { color: var(--head); background: var(--hair); }
.nav-link.on { color: var(--head); background: rgba(245,130,32,.12); box-shadow: inset 0 0 0 1px rgba(245,130,32,.26); }
.nav-right { display: inline-flex; align-items: center; gap: 8px; }
.nav-cta { font-family: var(--sans); }
.theme-toggle { width: 38px; height: 38px; border-radius: 999px; display: grid; place-items: center; cursor: pointer;
  background: var(--hair); border: 1px solid var(--hair-strong); color: var(--ink-2); transition: color .18s, background .18s, transform .18s; }
.theme-toggle:hover { color: var(--head); transform: rotate(-18deg); }
.theme-toggle svg { width: 17px; height: 17px; }
.nav-burger { display: none; }

/* ===================================================================
   BUTTONS
   =================================================================== */
.btn { display: inline-flex; align-items: center; gap: 10px; font-family: var(--sans); font-weight: 600;
  font-size: .96rem; padding: 13px 22px; border-radius: 999px; cursor: pointer; border: 1px solid transparent;
  transition: transform .14s cubic-bezier(.2,.8,.2,1), box-shadow .2s, background .2s, border-color .2s, color .2s; }
.btn svg { width: 17px; height: 17px; }
.btn-primary { color: var(--on-grad); background: var(--grad); font-weight: 700;
  box-shadow: 0 14px 34px -12px rgba(237,42,51,.5), inset 0 1px 0 rgba(255,255,255,.3); }
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 22px 46px -12px rgba(245,130,32,.6), inset 0 1px 0 rgba(255,255,255,.34); }
.btn-ghost { color: var(--ink); background: var(--hair); border-color: var(--hair-strong); }
.btn-ghost:hover { border-color: rgba(245,130,32,.5); color: var(--head); background: rgba(245,130,32,.08); }
.btn-ghost .ic { color: var(--orange); display: inline-flex; }
.btn-sm { padding: 9px 16px; font-size: .9rem; }

/* ===================================================================
   HERO
   =================================================================== */
.hero { position: relative; padding: clamp(70px, 13vh, 168px) 0 clamp(60px, 9vh, 120px); overflow: hidden; }
.hero-grid { display: grid; grid-template-columns: 1.15fr .85fr; gap: clamp(28px, 4vw, 64px); align-items: center; }
.hero-eyebrow { display: inline-flex; align-items: center; gap: 12px; margin-bottom: 26px;
  padding: 7px 14px 7px 10px; border: 1px solid var(--hair-strong); border-radius: 999px; background: var(--pill-bg); }
.hero-eyebrow .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px rgba(143,210,74,.16); animation: pulse 2.6s ease-in-out infinite; }
.hero-eyebrow span { font-family: var(--mono); font-size: .72rem; letter-spacing: .22em; text-transform: uppercase; color: var(--ink-2); }
@keyframes pulse { 0%,100% { box-shadow: 0 0 0 3px rgba(143,210,74,.18); } 50% { box-shadow: 0 0 0 7px rgba(143,210,74,.04); } }
.hero h1 { font-size: clamp(2.7rem, 6.4vw, 5.6rem); line-height: 1.015; letter-spacing: -.026em; }
.hero-lede { margin: 26px 0 34px; font-size: clamp(1.08rem, 1.5vw, 1.38rem); color: var(--ink-2); max-width: 40ch; }
.hero-actions { display: flex; gap: 14px; flex-wrap: wrap; }
.hero-meta { display: flex; gap: 30px; flex-wrap: wrap; margin-top: 46px; padding-top: 26px; border-top: 1px solid var(--hair); }
.hero-meta div { display: flex; flex-direction: column; gap: 5px; }
.hero-meta dt { font-family: var(--mono); font-size: .66rem; letter-spacing: .2em; text-transform: uppercase; color: var(--muted); }
.hero-meta dd { margin: 0; font-size: 1.04rem; color: var(--ink); font-weight: 600; }

.rise { opacity: 0; transform: translateY(16px); animation: rise .8s cubic-bezier(.2,.8,.2,1) forwards; }
.d1 { animation-delay: .05s; } .d2 { animation-delay: .15s; } .d3 { animation-delay: .25s; }
.d4 { animation-delay: .35s; } .d5 { animation-delay: .5s; } .d6 { animation-delay: .65s; }
@keyframes rise { to { opacity: 1; transform: translateY(0); } }

.readout { position: relative; border: 1px solid var(--hair-strong); border-radius: var(--r-lg);
  background: var(--readout-bg);
  box-shadow: 0 40px 90px -50px rgba(0,0,0,.95), inset 0 1px 0 rgba(255,255,255,.05);
  overflow: hidden; backdrop-filter: blur(6px); }
.readout::before { content: ""; position: absolute; inset: 0; pointer-events: none;
  background: radial-gradient(80% 60% at 80% -10%, rgba(143,210,74,.14), transparent 60%); }
.readout-bar { display: flex; align-items: center; gap: 9px; padding: 13px 16px; border-bottom: 1px solid var(--hair); }
.readout-bar .tl { display: flex; gap: 6px; }
.readout-bar .tl i { width: 9px; height: 9px; border-radius: 50%; background: var(--hair-strong); }
.readout-bar .tl i:first-child { background: rgba(143,210,74,.85); }
.readout-bar b { margin-left: auto; font-family: var(--mono); font-size: .68rem; letter-spacing: .18em; text-transform: uppercase; color: var(--muted); font-weight: 500; }
.readout-body { padding: 8px 16px 16px; }
.ro-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 11px 0; border-bottom: 1px dashed var(--hair); font-family: var(--mono); font-size: .82rem; }
.ro-row:last-child { border-bottom: 0; }
.ro-k { color: var(--ink-2); }
.ro-v { display: inline-flex; align-items: center; gap: 8px; color: var(--head); }
.ro-v .live { width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 10px var(--green-glow); animation: pulse 2.6s ease-in-out infinite; }
.ro-v.good { color: var(--green-2); }
.ro-scan { position: absolute; left: 0; right: 0; height: 90px; pointer-events: none;
  background: linear-gradient(180deg, transparent, rgba(143,210,74,.08), transparent); animation: scan 5.5s linear infinite; }
@keyframes scan { 0% { top: -90px; } 100% { top: 100%; } }

/* ===================================================================
   MISSION STATEMENT
   =================================================================== */
.statement { font-family: var(--display); font-weight: 400; font-size: clamp(1.7rem, 3.4vw, 2.9rem);
  line-height: 1.28; letter-spacing: -.014em; color: var(--head); max-width: 22ch; }
.statement .grad-text { font-style: italic; }
.statement-grid { display: grid; grid-template-columns: 1.4fr 1fr; gap: clamp(28px,5vw,72px); align-items: end; }
.statement-aside p { font-size: 1rem; line-height: 1.75; }
.statement-aside p + p { margin-top: 16px; }

/* ===================================================================
   RESEARCH ROWS
   =================================================================== */
.research-list { border-top: 1px solid var(--hair); }
.r-row { display: grid; grid-template-columns: 64px 1.1fr 1.4fr auto; gap: clamp(16px,3vw,40px); align-items: center;
  padding: 30px 8px; border-bottom: 1px solid var(--hair); position: relative; transition: background .25s; }
.r-row:hover { background: linear-gradient(90deg, rgba(245,130,32,.06), transparent 70%); }
.r-row:hover .r-arrow { color: var(--orange); transform: translate(3px,-3px); }
.r-num { font-family: var(--mono); font-size: .82rem; color: var(--muted); letter-spacing: .1em; }
.r-title { display: flex; align-items: center; gap: 14px; }
.r-ic { width: 40px; height: 40px; border-radius: 11px; flex: none; display: grid; place-items: center;
  color: var(--green-2); background: rgba(143,210,74,.10); border: 1px solid rgba(143,210,74,.22); }
.r-ic svg { width: 20px; height: 20px; }
.r-title h3 { font-size: 1.22rem; }
.r-desc { color: var(--ink-2); font-size: .98rem; line-height: 1.6; }
.r-arrow { color: var(--muted); transition: color .2s, transform .2s; display: inline-flex; }
.r-arrow svg { width: 22px; height: 22px; }
.tag { font-family: var(--mono); font-size: .64rem; letter-spacing: .14em; text-transform: uppercase;
  padding: 5px 9px; border-radius: 999px; border: 1px solid var(--hair-strong); color: var(--ink-2); white-space: nowrap; }
.tag.live { color: var(--green-2); border-color: rgba(143,210,74,.34); background: rgba(143,210,74,.10); }
.tag.research { color: var(--sky); border-color: rgba(111,168,208,.34); background: rgba(111,168,208,.08); }

/* ===================================================================
   CARDS
   =================================================================== */
.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 18px; }
.grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 18px; }
.grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 16px; }
.card { position: relative; border: 1px solid var(--hair); border-radius: var(--r-lg); padding: 26px 24px 28px;
  background: var(--card-bg);
  transition: transform .28s cubic-bezier(.2,.8,.2,1), border-color .28s, box-shadow .28s; overflow: hidden; }
.card::after { content: ""; position: absolute; inset: 0 0 auto 0; height: 1px; background: var(--grad); opacity: 0; transition: opacity .3s; }
.card:hover { transform: translateY(-4px); border-color: var(--hair-strong); box-shadow: 0 30px 60px -40px rgba(0,0,0,.55); }
.card:hover::after { opacity: .85; }
.card-ic { width: 44px; height: 44px; border-radius: 12px; display: grid; place-items: center; margin-bottom: 18px;
  color: var(--green-2); background: rgba(143,210,74,.10); border: 1px solid rgba(143,210,74,.22); }
.card-ic svg { width: 22px; height: 22px; }
.card h3 { margin-bottom: 10px; }
.card p { font-size: .96rem; line-height: 1.65; }

/* ===================================================================
   STATS
   =================================================================== */
.stats { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 1px; background: var(--hair);
  border: 1px solid var(--hair); border-radius: var(--r-lg); overflow: hidden; }
.stat { background: var(--bg-2); padding: 34px 26px; }
.stat dt { font-family: var(--display); font-size: clamp(2.2rem, 4vw, 3.2rem); line-height: 1; color: var(--head); letter-spacing: -.02em; }
.stat dd { margin: 12px 0 0; font-family: var(--mono); font-size: .72rem; letter-spacing: .16em; text-transform: uppercase; color: var(--muted); }
.stat .grad-text { display: inline; }

/* ===================================================================
   TEAM
   =================================================================== */
.team-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap: 18px; }
.member { border: 1px solid var(--hair); border-radius: var(--r-lg); padding: 24px; background: var(--member-bg); }
.member-photo { width: 58px; height: 58px; border-radius: 16px; display: grid; place-items: center; margin-bottom: 18px;
  font-family: var(--display); font-size: 1.5rem; color: var(--on-grad); background: var(--grad);
  box-shadow: 0 12px 26px -14px rgba(245,130,32,.6); }
.member b { font-size: 1.12rem; color: var(--head); font-weight: 600; }
.member .role { font-family: var(--mono); font-size: .7rem; letter-spacing: .14em; text-transform: uppercase; color: var(--orange); margin: 6px 0 12px; }
.member p { font-size: .92rem; line-height: 1.6; }

/* ===================================================================
   CTA
   =================================================================== */
.cta { position: relative; border: 1px solid var(--hair-strong); border-radius: var(--r-xl); overflow: hidden;
  padding: clamp(40px, 7vw, 84px); text-align: center; background: var(--cta-bg); }
.cta::before { content: ""; position: absolute; inset: 0; pointer-events: none;
  background: radial-gradient(60% 120% at 50% -10%, rgba(237,42,51,.16), transparent 60%); }
.cta::after { content: ""; position: absolute; inset: 0; pointer-events: none;
  background: radial-gradient(50% 120% at 88% 120%, rgba(245,130,32,.16), transparent 60%); }
.cta-inner { position: relative; z-index: 1; max-width: 760px; margin: 0 auto; }
.cta h2 { font-size: clamp(2rem, 4.4vw, 3.6rem); line-height: 1.05; }
.cta .lede { margin: 20px auto 32px; }
.cta-actions { display: flex; gap: 14px; justify-content: center; flex-wrap: wrap; }

/* ===================================================================
   FOOTER
   =================================================================== */
.footer { border-top: 1px solid var(--hair); padding: 60px 0 48px; }
.footer-top { display: grid; grid-template-columns: 1.4fr 1fr 1fr 1fr; gap: 32px; }
.footer-blurb { max-width: 36ch; color: var(--muted); font-size: .92rem; line-height: 1.65; margin-top: 16px; }
.footer h4 { font-family: var(--mono); font-size: .68rem; letter-spacing: .2em; text-transform: uppercase; color: var(--muted); margin: 0 0 16px; font-weight: 500; }
.footer ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 11px; }
.footer ul a { color: var(--ink-2); font-size: .94rem; transition: color .18s; }
.footer ul a:hover { color: var(--orange); }
.footer-chip { display: inline-flex; background: #fff; border-radius: 9px; padding: 5px 9px; box-shadow: 0 0 0 1px var(--hair-strong); }
.footer-chip img { height: 30px; width: auto; }
.footer-bottom { display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap;
  margin-top: 48px; padding-top: 26px; border-top: 1px solid var(--hair); }
.footer-bottom p { color: var(--faint); font-size: .82rem; margin: 0; }
.footer-bottom .legal { font-family: var(--mono); font-size: .68rem; letter-spacing: .08em; color: var(--faint); max-width: 62ch; }

/* ===================================================================
   PAGE HEADER (interior routes)
   =================================================================== */
.page-head { padding: clamp(80px, 14vh, 170px) 0 clamp(30px, 5vh, 60px); }
.page-head h1 { font-size: clamp(2.4rem, 5.6vw, 4.4rem); line-height: 1.04; letter-spacing: -.024em; max-width: 18ch; }
.page-head .lede { margin-top: 24px; }

.prose p { font-size: 1.05rem; line-height: 1.8; color: var(--ink-2); max-width: 66ch; }
.prose p + p { margin-top: 20px; }
.prose strong { color: var(--head); font-weight: 600; }

.deflist { display: grid; grid-template-columns: 1fr; gap: 0; border-top: 1px solid var(--hair); }
.def { display: grid; grid-template-columns: 240px 1fr; gap: 24px; padding: 24px 4px; border-bottom: 1px solid var(--hair); }
.def dt { font-family: var(--display); font-size: 1.18rem; color: var(--head); }
.def dd { margin: 0; color: var(--ink-2); font-size: .98rem; line-height: 1.65; }

/* ===================================================================
   SCROLL REVEAL — additive
   =================================================================== */
@supports (animation-timeline: view()) {
  @media (prefers-reduced-motion: no-preference) {
    .reveal { animation: reveal-up linear both; animation-timeline: view(); animation-range: entry 2% cover 22%; }
    @keyframes reveal-up { from { opacity: 0; transform: translateY(26px); } to { opacity: 1; transform: translateY(0); } }
  }
}

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after { animation: none !important; transition: none !important; }
  .rise { opacity: 1; transform: none; }
}

/* ===================================================================
   RESPONSIVE
   =================================================================== */
@media (max-width: 940px) {
  .hero-grid { grid-template-columns: 1fr; }
  .readout { max-width: 460px; }
  .statement-grid { grid-template-columns: 1fr; align-items: start; }
  .grid-4 { grid-template-columns: repeat(2, 1fr); }
  .stats { grid-template-columns: repeat(2, 1fr); }
  .footer-top { grid-template-columns: 1fr 1fr; gap: 28px; }
  .r-row { grid-template-columns: 40px 1fr auto; }
  .r-desc { grid-column: 2 / -1; grid-row: 2; }
}
@media (max-width: 720px) {
  .theme-root { font-size: 16px; }
  .nav-links { display: none; }
  .nav-burger { display: inline-flex; }
  .grid-2, .grid-3 { grid-template-columns: 1fr; }
  .def { grid-template-columns: 1fr; gap: 8px; }
  .hero-meta { gap: 22px; }
}
@media (max-width: 480px) {
  .grid-4, .stats { grid-template-columns: 1fr; }
  .footer-top { grid-template-columns: 1fr; }
}
"#;

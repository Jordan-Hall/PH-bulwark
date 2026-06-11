//! The child app's warm-dawn stylesheet — one source of truth for the journey's
//! look, injected once by `JourneyLayout`.

pub const CSS: &str = r#"
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600&family=Hanken+Grotesk:wght@400;500;600;700&display=swap');

:root {
  --cream: #FBF6EE;
  --card: #FFFDF9;
  --teal: #114B4A;
  --teal-2: #0C3837;
  --amber: #E8915B;
  --peach: #F4C89B;
  --sage: #8CB7A6;
  --ink: #2A2420;
  --muted: #756A60;
  --line: #ECE2D4;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body { background: var(--cream); }

.stage {
  position: relative;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  gap: 24px;
  padding: 40px 22px 56px;
  font-family: 'Hanken Grotesk', sans-serif;
  color: var(--ink);
  overflow: hidden;
}

/* warm dawn glow — atmosphere, not a flat fill */
.aurora {
  position: fixed; inset: -30% -10% auto -10%; height: 70vh; z-index: 0;
  background:
    radial-gradient(40% 50% at 25% 20%, rgba(244,200,155,.55), transparent 70%),
    radial-gradient(45% 55% at 85% 10%, rgba(140,183,166,.45), transparent 70%),
    radial-gradient(35% 45% at 60% 35%, rgba(232,145,91,.30), transparent 70%);
  filter: blur(8px);
  pointer-events: none;
}

/* ---- brand wordmark ---- */
.brand { position: relative; z-index: 1; font-family: 'Fraunces', serif; font-weight: 600; font-size: 18px; letter-spacing: .02em; color: var(--teal-2); }
.brand-accent { color: var(--amber); font-style: italic; }

/* ---- progress shield ---- */
.progress { position: relative; z-index: 1; display: flex; flex-direction: column; align-items: center; gap: 10px; }
.shield {
  position: relative; width: 58px; height: 66px;
  clip-path: polygon(50% 0, 100% 16%, 100% 56%, 50% 100%, 0 56%, 0 16%);
  background: rgba(17,75,74,.10);
  border: 0;
}
.shield-fill {
  position: absolute; left: 0; bottom: 0; width: 100%;
  background: linear-gradient(180deg, var(--sage), var(--teal));
  transition: height .7s cubic-bezier(.2,.8,.2,1);
}
.shield-glyph {
  position: absolute; inset: 0; display: grid; place-items: center;
  font-size: 26px; filter: grayscale(.2);
}
.progress-text { display: flex; flex-direction: column; align-items: center; gap: 1px; }
.step-no { font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--amber); font-weight: 700; }
.step-label { font-family: 'Fraunces', serif; font-size: 16px; color: var(--teal); font-weight: 500; }

/* ---- card ---- */
.card {
  position: relative; z-index: 1;
  width: 100%; max-width: 440px;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 26px;
  padding: 34px 28px 30px;
  box-shadow: 0 24px 60px -28px rgba(17,75,74,.35), 0 2px 0 rgba(255,255,255,.7) inset;
  animation: rise .6s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }

.hero { font-size: 52px; line-height: 1; margin-bottom: 14px; }
.hero.glow { filter: drop-shadow(0 8px 22px rgba(140,183,166,.7)); animation: pulse 2.6s ease-in-out infinite; }
@keyframes pulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.06); } }

/* ---- staggered entrance (used on facts, pills) ---- */
.stagger { animation: fade-up .55s cubic-bezier(.2,.8,.2,1) both; animation-delay: calc(var(--i, 0) * 90ms + 120ms); }
@keyframes fade-up { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

h1 { font-family: 'Fraunces', serif; font-weight: 500; font-size: 30px; line-height: 1.12; letter-spacing: -.01em; color: var(--teal-2); margin-bottom: 12px; }
h1 em, h1 br + em { font-style: italic; color: var(--amber); }
h2 { font-family: 'Fraunces', serif; font-weight: 500; font-size: 25px; color: var(--teal-2); margin-bottom: 8px; letter-spacing: -.01em; }
.lede { font-size: 15.5px; line-height: 1.55; color: var(--muted); margin-bottom: 22px; }
em { font-style: italic; }

/* ---- facts (how it works) ---- */
.facts { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; list-style: none; }
.fact { display: flex; gap: 13px; align-items: flex-start; padding: 14px 15px; border-radius: 16px; background: #FAF4EA; border: 1px solid var(--line); }
.fact.dont { background: #FBEEE6; border-color: #F3DEC9; }
.fact strong { display: block; font-size: 15px; color: var(--ink); margin-bottom: 2px; }
.fact span { display: block; font-size: 13.5px; color: var(--muted); line-height: 1.45; }
.tick, .cross { flex: none; width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-size: 14px; font-weight: 700; }
.tick { background: var(--sage); color: #fff; }
.cross { background: var(--amber); color: #fff; }

/* ---- permissions ---- */
.perms { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
.perm { display: flex; gap: 13px; align-items: center; padding: 14px; border-radius: 16px; border: 1px solid var(--line); background: #FAF4EA; transition: all .35s ease; }
.perm.granted { background: #EEF5F0; border-color: var(--sage); }
.perm-icon { flex: none; width: 42px; height: 42px; border-radius: 13px; background: #fff; display: grid; place-items: center; font-size: 21px; box-shadow: 0 4px 12px -6px rgba(17,75,74,.4); }
.perm-body { flex: 1; }
.perm-body strong { display: block; font-size: 14.5px; }
.perm-body span { display: block; font-size: 12.5px; color: var(--muted); line-height: 1.4; margin-top: 2px; }
.grant { flex: none; border: 0; background: var(--teal); color: var(--cream); font-family: inherit; font-weight: 600; font-size: 13px; padding: 9px 16px; border-radius: 999px; cursor: pointer; transition: transform .1s ease, background .2s; }
.grant:hover { background: var(--teal-2); }
.grant:active { transform: scale(.95); }
.perm-done { flex: none; width: 32px; height: 32px; border-radius: 50%; background: var(--sage); color: #fff; display: grid; place-items: center; font-weight: 700; }

/* ---- pairing code ---- */
/* The visible "segmented" slots sit behind one real, accessible input that
   owns the value and the caret. The input fades its own glyphs so the slots
   read as the value, while keyboards/screen-readers still see a normal field. */
.code-field { position: relative; margin: 8px 0 16px; }
.code-slots {
  position: absolute; inset: 0; display: flex; gap: 8px; padding: 8px;
  pointer-events: none; z-index: 1;
}
.slot {
  flex: 1; display: grid; place-items: center;
  font-family: 'Fraunces', serif; font-size: 28px; font-weight: 500; color: var(--teal-2);
  background: #FFFBF4; border: 2px solid var(--line); border-radius: 13px;
  transition: border-color .25s ease, background .25s ease, transform .25s cubic-bezier(.2,.8,.2,1);
}
.slot.filled { border-color: var(--sage); background: #F3F8F4; transform: translateY(-1px); animation: slot-pop .3s cubic-bezier(.2,.8,.2,1); }
@keyframes slot-pop { from { transform: scale(.9); } to { transform: scale(1) translateY(-1px); } }
.code-input {
  position: relative; z-index: 2;
  width: 100%; text-align: left; font-family: 'Fraunces', serif; font-size: 28px;
  letter-spacing: 0; padding: 8px 12px; height: 66px; margin: 0;
  border: 0; border-radius: 13px; background: transparent; color: transparent; caret-color: var(--amber);
  text-transform: uppercase; outline: none;
}
/* Keep the typed glyphs invisible (the slots show them) but caret + focus live here. */
.code-input { -webkit-text-fill-color: transparent; }
.code-field:focus-within .slot { border-color: var(--peach); }
.code-input::placeholder { color: transparent; }
/* Calm prompt shown (via RSX) only while the field is empty. */
.code-ghost {
  position: absolute; inset: 0; z-index: 1; display: grid; place-items: center; pointer-events: none;
  font-family: 'Hanken Grotesk', sans-serif; font-size: 14px; letter-spacing: .08em; color: #CBB89E;
}
.code-field:focus-within .code-ghost { opacity: .5; }

.hint {
  display: flex; align-items: center; gap: 9px; justify-content: center;
  font-size: 12.5px; line-height: 1.45; color: var(--muted);
  background: #FAF4EA; border: 1px solid var(--line); border-radius: 13px;
  padding: 10px 13px; margin-bottom: 22px; text-align: left;
}
.hint-icon { flex: none; font-size: 16px; }

/* ---- buttons / rows ---- */
.row { display: flex; gap: 10px; }
.row .primary { flex: 1; }
button { font-family: 'Hanken Grotesk', sans-serif; }
.primary {
  width: 100%; border: 0; background: var(--teal); color: var(--cream);
  font-weight: 600; font-size: 16px; padding: 15px 18px; border-radius: 16px; cursor: pointer;
  box-shadow: 0 14px 26px -14px rgba(17,75,74,.8); transition: transform .12s ease, background .2s, box-shadow .2s;
}
.primary:hover { background: var(--teal-2); }
.primary:active { transform: translateY(1px) scale(.99); }
.primary:disabled { background: #CDBFAE; color: #F3ECE0; box-shadow: none; cursor: not-allowed; }
.ghost { border: 0; background: transparent; color: var(--muted); font-weight: 600; font-size: 15px; padding: 15px 18px; border-radius: 16px; cursor: pointer; }
.ghost:hover { color: var(--teal); }

.fine { font-size: 12.5px; color: #9A8E80; margin-top: 16px; text-align: center; line-height: 1.5; }

/* ---- done ---- */
/* A calm "protection active" seal: a checkmark that settles in, with two soft
   rings that breathe outward once — rewarding, never loud. */
.seal { position: relative; width: 96px; height: 96px; margin: 4px auto 16px; }
.seal-core {
  position: absolute; inset: 18px; border-radius: 50%;
  background: radial-gradient(circle at 35% 30%, var(--sage), var(--teal));
  display: grid; place-items: center;
  box-shadow: 0 14px 30px -12px rgba(17,75,74,.6);
  animation: seal-in .6s cubic-bezier(.2,.9,.2,1) both;
}
.seal-check {
  color: #fff; font-size: 30px; font-weight: 700; line-height: 1;
  animation: check-in .45s cubic-bezier(.2,.9,.2,1) .28s both;
}
.seal-ring {
  position: absolute; inset: 0; border-radius: 50%;
  border: 2px solid var(--sage); opacity: 0;
  animation: ring-out 2.8s ease-out .5s infinite;
}
.seal-ring.two { animation-delay: 1.4s; }
@keyframes seal-in { from { opacity: 0; transform: scale(.6); } to { opacity: 1; transform: scale(1); } }
@keyframes check-in { from { opacity: 0; transform: scale(.4); } to { opacity: 1; transform: scale(1); } }
@keyframes ring-out { 0% { opacity: .55; transform: scale(.7); } 70% { opacity: 0; transform: scale(1.18); } 100% { opacity: 0; transform: scale(1.18); } }

.done-pills { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; margin: 8px 0 26px; }
.pill { font-size: 12.5px; font-weight: 600; color: var(--teal); background: #EEF5F0; border: 1px solid var(--sage); padding: 7px 13px; border-radius: 999px; }

/* Respect users who prefer less motion: keep the meaning, drop the movement. */
@media (prefers-reduced-motion: reduce) {
  .card, .stagger, .slot, .seal-core, .seal-check, .hero.glow { animation: none !important; }
  .seal-ring { display: none; }
  .shield-fill { transition: none; }
}
"#;

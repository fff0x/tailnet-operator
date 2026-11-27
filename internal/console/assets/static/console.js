// The overview's island: tooltips for the map and a periodic reload of the live part of the page.
// Without the module the map keeps its native <title> tooltips and the page shows the state when
// it loaded. The reload fetches the same server-rendered, escaped page; it never runs its scripts.

const live = document.querySelector("[data-live]");
const status = document.querySelector("[data-live-status]");

const tip = document.createElement("div");
tip.className = "map-tip";
tip.setAttribute("role", "tooltip");
tip.hidden = true;
document.body.append(tip);
let active = null;

function hide() {
  active = null;
  tip.hidden = true;
}

function show(node) {
  if (!node || !node.dataset.tip) return;
  active = node;
  tip.textContent = node.dataset.tip;
  tip.hidden = false;
  const r = node.getBoundingClientRect();
  const width = document.documentElement.clientWidth;
  const left = Math.max(8, Math.min(r.left, width - tip.offsetWidth - 8));
  tip.style.left = `${left + window.scrollX}px`;
  tip.style.top = `${r.bottom + window.scrollY + 6}px`;
}

// The native tooltip would double the custom one, so its text moves into data-tip.
function enhance(root) {
  root.querySelectorAll(".map__node").forEach((node) => {
    const title = node.querySelector("title");
    if (title) {
      node.dataset.tip = title.textContent;
      title.remove();
    }
  });
}

const nodeOf = (event) => event.target.closest?.(".map__node");
document.addEventListener("pointerover", (e) => { if (e.pointerType !== "touch" && nodeOf(e)) show(nodeOf(e)); });
document.addEventListener("pointerout", (e) => { if (active && nodeOf(e) === active && !active.contains(document.activeElement)) hide(); });
document.addEventListener("focusin", (e) => { if (nodeOf(e)) show(nodeOf(e)); else hide(); });
document.addEventListener("focusout", (e) => { if (nodeOf(e) === active) hide(); });
document.addEventListener("click", (e) => { if (nodeOf(e)) show(nodeOf(e)); });
document.addEventListener("pointerdown", (e) => { if (!nodeOf(e)) hide(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
window.addEventListener("blur", hide);

function say(text) {
  if (status) status.textContent = text;
}

// The session has ended: the map gives way to a notice and polling stops.
function expire() {
  hide();
  const p = document.createElement("p");
  p.className = "notice notice--bad";
  const a = document.createElement("a");
  a.href = "/auth/login?return=" + encodeURIComponent(location.pathname);
  a.textContent = "Sign in again";
  p.append("Session expired. ", a, ".");
  live.replaceChildren(p);
  say("Session expired.");
}

// refresh returns the live part's HTML as last sent, or null when polling must stop.
async function refresh(last) {
  let resp;
  try {
    resp = await fetch(location.href, { redirect: "manual", cache: "no-store", credentials: "same-origin" });
  } catch {
    say("The console is unreachable; this is the last state it sent.");
    return last;
  }
  if (resp.type === "opaqueredirect" || resp.status === 401 || resp.status === 403) {
    expire();
    return null;
  }
  if (!resp.ok) {
    say(`The console answered ${resp.status}; this is the last state it sent.`);
    return last;
  }
  const next = new DOMParser().parseFromString(await resp.text(), "text/html").querySelector("[data-live]");
  if (!next) {
    expire();
    return null;
  }
  // A focused entry would lose its focus; the swap waits for the next round.
  const html = next.innerHTML;
  if (html !== last && live.contains(document.activeElement)) {
    say("Live: a change waits while an entry has the focus.");
    return last;
  }
  if (html !== last) {
    live.replaceChildren(...document.adoptNode(next).childNodes);
    enhance(live);
    if (active && !live.contains(active)) hide();
    last = html;
  }
  say(`Live: updated ${new Date().toLocaleTimeString()}.`);
  return last;
}

if (live) {
  const every = Number(live.dataset.poll) || 0;
  let last = live.innerHTML;
  enhance(live);
  if (every > 0) {
    let timer;
    let busy = false;
    const tick = async () => {
      clearTimeout(timer);
      if (busy || last === null || document.hidden) return;
      busy = true;
      last = await refresh(last);
      busy = false;
      if (last !== null && !document.hidden) timer = setTimeout(tick, every);
    };
    document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
    say(`Live: updates every ${Math.round(every / 1000)} s.`);
    timer = setTimeout(tick, every);
  }
}

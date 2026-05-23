const $ = (id) => document.getElementById(id);

function sendMsg(type) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type }, (resp) => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
      else resolve(resp || { ok: false });
    });
  });
}

function shortHash(h) {
  if (!h) return "—";
  return h.length > 14 ? `${h.slice(0, 10)}…${h.slice(-4)}` : h;
}

function render(state) {
  const { bridge, policy } = state || {};
  const bridgeEl = $("bridge");
  if (bridge?.connected) {
    bridgeEl.textContent = "connected";
    bridgeEl.className = "pill pill--ok";
  } else {
    bridgeEl.textContent = "offline";
    bridgeEl.className = "pill pill--err";
  }
  $("transport").textContent = bridge?.mode || "—";
  $("policy").textContent = shortHash(policy?.policy_version_hash);
  $("source").textContent = policy?.source || "—";
}

async function refresh() {
  const state = await sendMsg("aetherix.status");
  if (state.ok) render(state);
}

$("resync").addEventListener("click", async () => {
  $("resync").disabled = true;
  $("resync").textContent = "Re-syncing…";
  await sendMsg("aetherix.resync");
  await refresh();
  $("resync").textContent = "Re-sync policy now";
  $("resync").disabled = false;
});

refresh();

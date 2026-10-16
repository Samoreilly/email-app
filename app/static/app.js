// Copy-to-clipboard buttons: <button class="copy" data-copy="text">Copy</button>
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  e.preventDefault();
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    const old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = old), 1500);
  } catch {
    window.prompt("Copy this:", btn.dataset.copy);
  }
});

// Confirm dangerous actions: <form data-confirm="Are you sure?">
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) e.preventDefault();
});

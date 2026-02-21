document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".js-copy-code");
    if (!btn) return;

    if (btn.disabled) return;

    try {
        btn.disabled = true;

        const selector = btn.dataset.clipboardTarget;
        const container = btn.closest(".code-block__body");
        const codeEl = container?.querySelector(selector);
        if (!codeEl) return;

        const raw = codeEl.textContent;
        const cleaned = raw.replace(/\s+/g, " ").trim();

        await navigator.clipboard.writeText(cleaned);

        btn.innerHTML = `<i class="fa-solid fa-check"></i>`;

        setTimeout(() => {
            btn.innerHTML = `<i class="fa-regular fa-copy"></i>`;
            btn.disabled = false;
        }, 3000);

    } catch (e) {
        btn.disabled = false;
        console.error("COPY FAIL:", e);
    }
});
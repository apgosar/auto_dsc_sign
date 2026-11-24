/* DSC Signer front-end: API helper, browser fingerprint, PDF.js placement canvas,
   job polling, token badge and admin panel actions. Vanilla JS, no build step. */
(function () {
  "use strict";

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  async function api(url, opts) {
    opts = opts || {};
    const headers = { "X-Requested-With": "fetch", "X-CSRF-Token": csrf() };
    let body;
    if (opts.form) {
      body = opts.form;
    } else if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    const res = await fetch(url, {
      method: opts.method || (body ? "POST" : "GET"),
      headers, body, credentials: "same-origin",
    });
    if (res.status === 401 && !opts.noRedirect) {
      window.location.href = "/login";
      throw new Error("Session expired");
    }
    let data = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) data = await res.json();
    if (!res.ok) {
      let msg = data && data.detail ? data.detail : `Request failed (${res.status})`;
      if (Array.isArray(msg)) msg = msg.map((e) => `${(e.loc || []).slice(-1)[0]}: ${e.msg}`).join("; ");
      throw new Error(msg);
    }
    return data;
  }

  function showMsg(el, text, kind) {
    if (!el) return;
    el.textContent = text;
    el.className = "text-sm rounded-lg p-3 " + (kind === "error"
      ? "bg-red-50 border border-red-200 text-red-800"
      : kind === "ok" ? "bg-green-50 border border-green-200 text-green-800"
      : "bg-blue-50 border border-blue-200 text-blue-800");
    el.classList.remove("hidden");
  }

  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleString("en-IN", { timeZone: "Asia/Kolkata", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  const ZOOM_STEPS = [0.5, 0.67, 0.8, 1, 1.25, 1.5, 2, 2.5, 3];
  function nextZoom(current, dir) {
    if (dir > 0) return ZOOM_STEPS.find((z) => z > current + 0.01) || ZOOM_STEPS[ZOOM_STEPS.length - 1];
    return [...ZOOM_STEPS].reverse().find((z) => z < current - 0.01) || ZOOM_STEPS[0];
  }

  function bindLogout() {
    const b = $("#logout-btn");
    if (!b) return;
    b.addEventListener("click", async () => {
      try { await api("/api/logout", { method: "POST", body: {} }); } catch (_) { /* ignore */ }
      window.location.href = "/login";
    });
  }

  // ------------------------------------------------------------------ fingerprint
  async function fingerprint() {
    const s = window.screen || {};
    const parts = [
      navigator.userAgent,
      `${Math.max(s.width || 0, s.height || 0)}x${Math.min(s.width || 0, s.height || 0)}x${s.colorDepth || 0}`,
      Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      navigator.language || "",
      navigator.platform || "",
      navigator.hardwareConcurrency || 0,
      navigator.deviceMemory || 0,
      navigator.maxTouchPoints || 0,
    ].join("|");
    try {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(parts));
      return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (_) {
      // crypto.subtle needs a secure context (https / localhost); fall back to a simple hash
      let h = 0;
      for (let i = 0; i < parts.length; i++) h = (Math.imul(31, h) + parts.charCodeAt(i)) | 0;
      return "x" + (h >>> 0).toString(16);
    }
  }

  // ================================================================== LOGIN
  function initLogin() {
    const form = $("#login-form"), err = $("#login-error"), btn = $("#login-btn");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.classList.add("hidden");
      btn.disabled = true; btn.textContent = "Signing in…";
      try {
        const data = await api("/api/login", {
          body: { username: form.username.value.trim(), password: form.password.value, fingerprint: await fingerprint() },
          noRedirect: true,
        });
        window.location.href = data.redirect || "/";
      } catch (ex) {
        err.textContent = ex.message;
        err.classList.remove("hidden");
        btn.disabled = false; btn.textContent = "Sign in";
      }
    });
  }

  // ================================================================== DASHBOARD
  function initDashboard(cfg) {
    bindLogout();
    const state = {
      files: [], mode: "visual",
      pdf: null, pageNum: 1, pageCount: 0, scale: 1, rendering: false,
      box: null, // {x,y,w,h} as fractions of the displayed page
      showAll: false,
    };
    if (window.pdfjsLib) {
      pdfjsLib.GlobalWorkerOptions.workerSrc = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
    }

    // ---------------- files
    const fileInput = $("#file-input"), drop = $("#drop-zone"), list = $("#file-list");
    function setFiles(fl) {
      const pdfs = Array.from(fl).filter((f) => f.type === "application/pdf" || /\.pdf$/i.test(f.name));
      state.files = pdfs;
      list.textContent = "";
      pdfs.forEach((f, i) => {
        const li = document.createElement("li");
        li.className = "flex justify-between gap-2 bg-slate-50 rounded px-2 py-1";
        const n = document.createElement("span"); n.className = "truncate"; n.textContent = (i === 0 ? "👁 " : "") + f.name;
        const s = document.createElement("span"); s.className = "text-slate-500 text-xs whitespace-nowrap"; s.textContent = (f.size / 1048576).toFixed(2) + " MB";
        li.append(n, s); list.append(li);
      });
      if (pdfs.length) loadPreview(pdfs[0]); else clearPreview();
      updateSubmit();
    }
    fileInput.addEventListener("change", () => setFiles(fileInput.files));
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("border-blue-500", "bg-blue-50"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("border-blue-500", "bg-blue-50"); }));
    drop.addEventListener("drop", (e) => { if (e.dataTransfer && e.dataTransfer.files) setFiles(e.dataTransfer.files); });

    // ---------------- tabs
    $$(".tab-btn").forEach((b) => b.addEventListener("click", () => {
      state.mode = b.dataset.mode;
      $$(".tab-btn").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
      $$(".mode-panel").forEach((p) => p.classList.toggle("hidden", p.dataset.mode !== state.mode));
      $("#sig-box").style.display = state.mode === "visual" && state.box ? "block" : "none";
      $("#pdf-stage").style.cursor = state.mode === "visual" ? "crosshair" : "default";
      updateSubmit();
    }));
    const pPages = $("#p-pages"), pPos = $("#p-position");
    pPages.addEventListener("change", () => $("#p-pagelist-wrap").classList.toggle("hidden", pPages.value !== "specific"));
    function updateMarginLabels() {
      const custom = pPos.value === "custom";
      $("#p-mx-lbl").textContent = custom ? "X from left (pt)" : "Side margin (pt)";
      $("#p-my-lbl").textContent = custom ? "Y from bottom (pt)" : "Top/bottom margin (pt)";
    }
    pPos.addEventListener("change", updateMarginLabels); updateMarginLabels();

    // ---------------- PDF preview
    const canvas = $("#pdf-canvas"), stage = $("#pdf-stage"), boxEl = $("#sig-box"), scroll = $("#pdf-scroll");
    function clearPreview() {
      state.pdf = null; state.pageCount = 0;
      stage.classList.add("hidden"); $("#pdf-empty").classList.remove("hidden");
      $("#preview-name").textContent = ""; updatePageNav();
    }
    async function loadPreview(file) {
      if (!window.pdfjsLib) { $("#pdf-empty").textContent = "PDF.js failed to load (check internet access)."; return; }
      try {
        const buf = await file.arrayBuffer();
        state.pdf = await pdfjsLib.getDocument({ data: buf }).promise;
        state.pageCount = state.pdf.numPages;
        state.pageNum = Math.min(state.pageNum, state.pageCount) || 1;
        $("#preview-name").textContent = "· " + file.name;
        $("#pdf-empty").classList.add("hidden"); stage.classList.remove("hidden");
        await renderPage();
      } catch (ex) {
        clearPreview();
        $("#pdf-empty").textContent = "Could not render this PDF: " + ex.message;
      }
    }
    async function renderPage() {
      if (!state.pdf) return;
      if (state.rendering) { state.renderAgain = true; return; }
      state.rendering = true;
      try {
        const page = await state.pdf.getPage(state.pageNum);
        const base = page.getViewport({ scale: 1 });
        const avail = Math.max(280, scroll.clientWidth - 32);
        state.fitScale = Math.min(1.6, avail / base.width);
        state.scale = state.zoom || state.fitScale;
        const vp = page.getViewport({ scale: state.scale });
        const dpr = window.devicePixelRatio || 1;
        canvas.width = Math.floor(vp.width * dpr); canvas.height = Math.floor(vp.height * dpr);
        canvas.style.width = vp.width + "px"; canvas.style.height = vp.height + "px";
        const ctx = canvas.getContext("2d");
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        await page.render({ canvasContext: ctx, viewport: vp }).promise;
        state.pagePt = { w: base.width, h: base.height };
        drawBox(); updatePageNav();
      } finally {
        state.rendering = false;
        if (state.renderAgain) { state.renderAgain = false; renderPage(); }
      }
    }
    function updatePageNav() {
      const has = !!state.pdf;
      const inp = $("#page-input");
      inp.disabled = !has;
      inp.max = state.pageCount || 1;
      if (document.activeElement !== inp) inp.value = has ? state.pageNum : 1;
      $("#page-total").textContent = has ? `of ${state.pageCount}` : "of –";
      $("#prev-page").disabled = !has || state.pageNum <= 1;
      $("#next-page").disabled = !has || state.pageNum >= state.pageCount;
      ["#zoom-in", "#zoom-out", "#zoom-fit"].forEach((s) => { $(s).disabled = !has; });
      $("#zoom-info").textContent = state.zoom ? Math.round(state.zoom * 100) + "%" : "Fit";
    }
    function goToPage(n) {
      if (!state.pdf) return;
      n = clamp(Math.round(n) || 1, 1, state.pageCount);
      if (n !== state.pageNum) { state.pageNum = n; scroll.scrollTop = 0; renderPage(); } else updatePageNav();
    }
    $("#prev-page").addEventListener("click", () => goToPage(state.pageNum - 1));
    $("#next-page").addEventListener("click", () => goToPage(state.pageNum + 1));
    $("#goto-form").addEventListener("submit", (e) => { e.preventDefault(); goToPage(+$("#page-input").value); $("#page-input").blur(); });
    $("#page-input").addEventListener("change", () => goToPage(+$("#page-input").value));
    $("#zoom-in").addEventListener("click", () => { state.zoom = nextZoom(state.zoom || state.fitScale, +1); renderPage(); });
    $("#zoom-out").addEventListener("click", () => { state.zoom = nextZoom(state.zoom || state.fitScale, -1); renderPage(); });
    $("#zoom-fit").addEventListener("click", () => { state.zoom = null; renderPage(); });
    let resizeT; window.addEventListener("resize", () => { clearTimeout(resizeT); resizeT = setTimeout(renderPage, 200); });

    // ---------------- signature box (stored as fractions of the page)
    const cw = () => canvas.clientWidth, ch = () => canvas.clientHeight;
    function drawBox() {
      if (!state.box || state.mode !== "visual") { boxEl.style.display = "none"; updateVisualInfo(); updateSubmit(); return; }
      const b = state.box;
      Object.assign(boxEl.style, { display: "block", left: b.x * cw() + "px", top: b.y * ch() + "px", width: b.w * cw() + "px", height: b.h * ch() + "px" });
      updateVisualInfo(); updateSubmit();
    }
    function updateVisualInfo() {
      const el = $("#visual-info");
      if (!state.box || !state.pagePt) { el.textContent = "No box drawn yet."; return; }
      const b = state.box, p = state.pagePt;
      el.textContent = `Page ${state.pageNum}: ${Math.round(b.w * p.w)} × ${Math.round(b.h * p.h)} pt at x=${Math.round(b.x * p.w)}, y=${Math.round(b.y * p.h)} pt from top-left.`;
    }
    const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);
    function localPoint(e) {
      const r = canvas.getBoundingClientRect();
      return { x: clamp((e.clientX - r.left) / r.width, 0, 1), y: clamp((e.clientY - r.top) / r.height, 0, 1) };
    }
    let drag = null;
    stage.addEventListener("pointerdown", (e) => {
      if (state.mode !== "visual" || !state.pdf) return;
      e.preventDefault();
      const p = localPoint(e);
      if (e.target.classList.contains("handle")) drag = { kind: "resize", start: p, orig: { ...state.box } };
      else if (e.target === boxEl || boxEl.contains(e.target)) drag = { kind: "move", start: p, orig: { ...state.box } };
      else { drag = { kind: "draw", start: p }; state.box = { x: p.x, y: p.y, w: 0, h: 0 }; }
      stage.setPointerCapture(e.pointerId);
    });
    stage.addEventListener("pointermove", (e) => {
      if (!drag) return;
      const p = localPoint(e), s = drag.start;
      if (drag.kind === "draw") {
        state.box = { x: Math.min(s.x, p.x), y: Math.min(s.y, p.y), w: Math.abs(p.x - s.x), h: Math.abs(p.y - s.y) };
      } else if (drag.kind === "move") {
        const o = drag.orig;
        state.box = { ...o, x: clamp(o.x + p.x - s.x, 0, 1 - o.w), y: clamp(o.y + p.y - s.y, 0, 1 - o.h) };
      } else {
        const o = drag.orig;
        state.box = { ...o, w: clamp(o.w + p.x - s.x, 0.02, 1 - o.x), h: clamp(o.h + p.y - s.y, 0.015, 1 - o.y) };
      }
      drawBox();
    });
    const endDrag = () => {
      if (drag && drag.kind === "draw" && state.box && (state.box.w < 0.02 || state.box.h < 0.015)) state.box = null;
      drag = null; drawBox();
    };
    stage.addEventListener("pointerup", endDrag);
    stage.addEventListener("pointercancel", endDrag);
    $("#clear-box").addEventListener("click", () => { state.box = null; drawBox(); });
    $$(".size-preset").forEach((b) => b.addEventListener("click", () => {
      if (!state.pagePt) return;
      const w = Math.min(1, +b.dataset.w / state.pagePt.w), h = Math.min(1, +b.dataset.h / state.pagePt.h);
      const m = 36;
      if (state.box) {
        state.box = { x: clamp(state.box.x, 0, 1 - w), y: clamp(state.box.y, 0, 1 - h), w, h };
      } else {
        state.box = { x: clamp(1 - w - m / state.pagePt.w, 0, 1 - w), y: clamp(1 - h - m / state.pagePt.h, 0, 1 - h), w, h };
      }
      drawBox();
    }));

    // ---------------- submit
    const submitBtn = $("#submit-btn"), submitMsg = $("#submit-msg");
    function updateSubmit() {
      let ok = state.files.length > 0;
      if (state.mode === "visual") ok = ok && !!state.box && !!state.pdf;
      submitBtn.disabled = !ok;
    }
    function collectParams() {
      const reason = $("#reason").value.trim(), location = $("#location").value.trim();
      if (state.mode === "visual") {
        const b = state.box;
        return { page_number: state.pageNum, x_pct: +b.x.toFixed(6), y_pct: +b.y.toFixed(6), w_pct: +b.w.toFixed(6), h_pct: +b.h.toFixed(6), reason, location };
      }
      if (state.mode === "preset") {
        return { pages: pPages.value, page_list: $("#p-pagelist").value.trim(), position: pPos.value,
          margin_x: +$("#p-mx").value, margin_y: +$("#p-my").value, width: +$("#p-w").value, height: +$("#p-h").value, reason, location };
      }
      return { text: $("#a-text").value.trim(), placement: $("#a-placement").value, match: $("#a-match").value,
        width: +$("#a-w").value, height: +$("#a-h").value, reason, location };
    }
    submitBtn.addEventListener("click", async () => {
      if (state.mode === "anchor" && !$("#a-text").value.trim()) { showMsg(submitMsg, "Enter the anchor text to search for.", "error"); return; }
      if (state.mode === "preset" && pPages.value === "specific" && !$("#p-pagelist").value.trim()) { showMsg(submitMsg, "Enter the page number(s).", "error"); return; }
      const fd = new FormData();
      state.files.forEach((f) => fd.append("files", f, f.name));
      fd.append("mode", state.mode);
      fd.append("params", JSON.stringify(collectParams()));
      submitBtn.disabled = true; submitBtn.textContent = "Uploading…";
      try {
        const data = await api("/api/jobs", { method: "POST", form: fd });
        data.jobs.filter((j) => j.status !== "FAILED").forEach((j) => watched.add(j.id));
        const failed = data.jobs.filter((j) => j.status === "FAILED");
        if (failed.length) showMsg(submitMsg, `${data.jobs.length - failed.length} queued, ${failed.length} rejected: ` + failed.map((j) => `${j.filename}: ${j.error}`).join(" | "), "error");
        else showMsg(submitMsg, `${data.jobs.length} document(s) queued for signing.`, "ok");
        fileInput.value = ""; setFiles([]); state.box = null; drawBox();
        refreshJobs();
      } catch (ex) {
        showMsg(submitMsg, ex.message, "error");
      } finally {
        submitBtn.textContent = "Queue for signing"; updateSubmit();
      }
    });

    // ---------------- jobs table
    const STATUS = {
      QUEUED: "bg-amber-100 text-amber-800", PROCESSING: "bg-blue-100 text-blue-800",
      COMPLETED: "bg-green-100 text-green-800", FAILED: "bg-red-100 text-red-800", EXPIRED: "bg-slate-100 text-slate-500",
    };
    const MODE = { visual: "Visual", preset: "Page/Position", anchor: "Text anchor" };

    // Jobs submitted from this tab: when one finishes, its signed PDF opens automatically.
    const watched = new Set();
    const toPreview = [];
    const autoBox = $("#auto-preview");
    try { const v = localStorage.getItem("dsc.autoPreview"); if (v !== null) autoBox.checked = v === "1"; } catch (_) {}
    autoBox.addEventListener("change", () => { try { localStorage.setItem("dsc.autoPreview", autoBox.checked ? "1" : "0"); } catch (_) {} });
    const viewer = createSignedViewer(() => { if (toPreview.length && autoBox.checked) viewer.open(toPreview.shift()); });

    // Admins only: "All users" shows everyone's documents with an Owner column.
    const allBox = $("#show-all-jobs");
    if (allBox) {
      try { allBox.checked = localStorage.getItem("dsc.showAllJobs") === "1"; } catch (_) {}
      allBox.addEventListener("change", () => {
        try { localStorage.setItem("dsc.showAllJobs", allBox.checked ? "1" : "0"); } catch (_) {}
        refreshJobs();
      });
    }

    async function refreshJobs() {
      let data;
      const showAll = !!(allBox && allBox.checked);
      try { data = await api("/api/jobs" + (showAll ? "?scope=all" : "")); } catch (_) { return; }
      const allMode = data.scope === "all";
      $$(".owner-col").forEach((th) => th.classList.toggle("hidden", !allMode));
      $("#queue-title").textContent = allMode ? "Signing queue (all users)" : "My signing queue";
      data.jobs.forEach((j) => {
        if (!watched.has(j.id)) return;
        if (j.status === "COMPLETED" && j.download_url) { watched.delete(j.id); toPreview.push(j); }
        else if (j.status === "FAILED" || j.status === "EXPIRED") watched.delete(j.id);
      });
      if (toPreview.length && autoBox.checked && !viewer.isOpen()) viewer.open(toPreview.shift());
      else if (!autoBox.checked) toPreview.length = 0;
      const body = $("#jobs-body");
      body.textContent = "";
      if (!data.jobs.length) {
        const tr = document.createElement("tr"); const td = document.createElement("td");
        td.colSpan = allMode ? 6 : 5; td.className = "py-6 text-center text-slate-400"; td.textContent = "No jobs yet.";
        tr.append(td); body.append(tr); return;
      }
      data.jobs.forEach((j) => {
        const tr = document.createElement("tr"); tr.className = "border-b align-top";
        const c1 = document.createElement("td"); c1.className = "py-2 pr-3 max-w-[16rem]";
        const nm = document.createElement("div"); nm.className = "truncate font-medium"; nm.textContent = j.filename; nm.title = j.filename; c1.append(nm);
        if (j.error) { const er = document.createElement("div"); er.className = "text-xs text-red-700 mt-0.5 whitespace-normal"; er.textContent = j.error; c1.append(er); }
        const c2 = document.createElement("td"); c2.className = "pr-3 text-xs"; c2.textContent = MODE[j.mode] || j.mode;
        if (j.signature_count > 1) c2.textContent += ` (${j.signature_count}×)`;
        const c3 = document.createElement("td"); c3.className = "pr-3";
        const b = document.createElement("span"); b.className = "badge " + (STATUS[j.status] || ""); b.textContent = j.status + (j.queue_position ? ` #${j.queue_position}` : ""); c3.append(b);
        const c4 = document.createElement("td"); c4.className = "pr-3 text-xs whitespace-nowrap"; c4.textContent = fmtTime(j.created_at);
        const c5 = document.createElement("td"); c5.className = "text-right whitespace-nowrap";
        if (j.download_url) {
          const pv = document.createElement("button"); pv.className = "btn btn-ghost btn-sm mr-1"; pv.textContent = "Preview";
          pv.addEventListener("click", () => viewer.open(j));
          const a = document.createElement("a"); a.href = j.download_url; a.className = "btn btn-primary btn-sm"; a.textContent = "Download";
          c5.append(pv, a);
        }
        if (j.status !== "PROCESSING") {
          const d = document.createElement("button"); d.className = "btn btn-ghost btn-sm ml-1"; d.textContent = "✕"; d.title = "Remove";
          d.addEventListener("click", async () => { try { await api(`/api/jobs/${j.id}`, { method: "DELETE" }); refreshJobs(); } catch (ex) { alert(ex.message); } });
          c5.append(d);
        }
        const cells = [c1];
        if (allMode) { const co = document.createElement("td"); co.className = "pr-3 text-xs"; co.textContent = j.owner || ""; if (j.mine) co.textContent += " (you)"; cells.push(co); }
        cells.push(c2, c3, c4, c5);
        tr.append(...cells); body.append(tr);
      });
    }

    // ---------------- token badge
    async function refreshToken() {
      let s;
      try { s = await api("/api/token-status"); } catch (_) { return; }
      const badge = $("#token-badge"), dot = $(".dot", badge), txt = $("#token-text");
      badge.className = "badge " + (s.connected ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800");
      dot.className = "dot " + (s.connected ? "bg-green-500" : "bg-red-500");
      txt.textContent = s.connected ? `Token ready${s.cert_subject ? " · " + s.cert_subject : ""}` : `Token: ${s.state}`;
      badge.title = s.message + (s.queue_length ? ` · ${s.queue_length} in queue` : "");
    }

    refreshJobs(); refreshToken();
    setInterval(refreshJobs, 3000);
    setInterval(refreshToken, 10000);
  }

  // ================================================================== SIGNED PDF VIEWER
  // Continuous-scroll PDF.js viewer in a modal. Pages render lazily as they scroll into view,
  // so long documents open quickly. Signature widgets are drawn from their appearance streams.
  function createSignedViewer(onClose) {
    const modal = $("#signed-modal"), scroller = $("#signed-scroll"), pagesEl = $("#signed-pages");
    const pageInput = $("#signed-page-input");
    const v = { pdf: null, job: null, zoom: null, sizes: [], token: 0, observer: null, current: 1 };

    function isOpen() { return !modal.classList.contains("hidden"); }

    function close() {
      if (!isOpen()) return;
      modal.classList.add("hidden");
      document.body.style.overflow = "";
      v.token++;
      if (v.observer) v.observer.disconnect();
      if (v.pdf) { v.pdf.destroy(); v.pdf = null; }
      pagesEl.textContent = "";
      onClose && onClose();
    }

    function fitScale() {
      const maxW = Math.max(...v.sizes.map((s) => s.w), 1);
      return Math.min(1.5, Math.max(0.3, (scroller.clientWidth - 40) / maxW));
    }

    function message(text, cls) {
      pagesEl.textContent = "";
      const p = document.createElement("p"); p.className = "text-sm mt-10 " + (cls || "text-slate-500"); p.textContent = text;
      pagesEl.append(p);
    }

    async function renderInto(wrap, token) {
      if (wrap.dataset.rendered === "1" || !v.pdf) return;
      wrap.dataset.rendered = "1";
      const n = +wrap.dataset.page, scale = v.zoom || fitScale();
      const page = await v.pdf.getPage(n);
      if (token !== v.token) return;
      const vp = page.getViewport({ scale });
      const dpr = window.devicePixelRatio || 1;
      const c = document.createElement("canvas");
      c.width = Math.floor(vp.width * dpr); c.height = Math.floor(vp.height * dpr);
      c.style.width = vp.width + "px"; c.style.height = vp.height + "px";
      const ctx = c.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      await page.render({ canvasContext: ctx, viewport: vp, annotationMode: pdfjsLib.AnnotationMode.ENABLE }).promise;
      if (token !== v.token) return;
      wrap.textContent = ""; wrap.append(c);
    }

    function layout(keepPage) {
      const token = ++v.token;
      if (v.observer) v.observer.disconnect();
      pagesEl.textContent = "";
      const scale = v.zoom || fitScale();
      $("#signed-zoom-info").textContent = v.zoom ? Math.round(v.zoom * 100) + "%" : "Fit";
      v.observer = new IntersectionObserver((entries) => {
        entries.forEach((e) => { if (e.isIntersecting) renderInto(e.target, token); });
      }, { root: scroller, rootMargin: "600px 0px" });
      v.sizes.forEach((s, i) => {
        const wrap = document.createElement("div");
        wrap.className = "bg-white shadow relative flex items-center justify-center text-slate-300 text-sm";
        wrap.style.width = s.w * scale + "px"; wrap.style.height = s.h * scale + "px";
        wrap.dataset.page = String(i + 1);
        wrap.textContent = `Page ${i + 1}`;
        pagesEl.append(wrap);
        v.observer.observe(wrap);
      });
      if (keepPage) scrollToPage(keepPage, false);
    }

    function scrollToPage(n, smooth) {
      n = Math.min(Math.max(Math.round(n) || 1, 1), v.sizes.length || 1);
      const el = pagesEl.children[n - 1];
      if (el) scroller.scrollTo({ top: el.offsetTop - 12, behavior: smooth ? "smooth" : "auto" });
      v.current = n; pageInput.value = n;
    }

    scroller.addEventListener("scroll", () => {
      if (!v.sizes.length) return;
      const mid = scroller.scrollTop + scroller.clientHeight / 3;
      let n = 1;
      for (const el of pagesEl.children) { if (el.offsetTop <= mid) n = +el.dataset.page || n; else break; }
      v.current = n;
      if (document.activeElement !== pageInput) pageInput.value = n;
    });

    async function open(job) {
      if (!window.pdfjsLib) { window.open(job.download_url + "?inline=1", "_blank"); return; }
      if (isOpen()) close();
      v.job = job; v.zoom = null; v.sizes = [];
      $("#signed-title").textContent = job.filename.replace(/\.pdf$/i, "") + "_signed.pdf";
      $("#signed-download").href = job.download_url;
      $("#signed-page-total").textContent = "of –"; pageInput.value = 1;
      modal.classList.remove("hidden");
      document.body.style.overflow = "hidden";
      message("Loading signed PDF…");
      const token = ++v.token;
      try {
        const res = await fetch(job.download_url + "?inline=1", { credentials: "same-origin" });
        if (!res.ok) throw new Error(res.status === 404 ? "The signed file has expired or was removed." : `Could not load (${res.status})`);
        const buf = await res.arrayBuffer();
        if (token !== v.token) return;
        v.pdf = await pdfjsLib.getDocument({ data: buf }).promise;
        for (let i = 1; i <= v.pdf.numPages; i++) {
          const vp = (await v.pdf.getPage(i)).getViewport({ scale: 1 });
          v.sizes.push({ w: vp.width, h: vp.height });
        }
        if (token !== v.token) return;
        $("#signed-page-total").textContent = `of ${v.pdf.numPages}`;
        pageInput.max = v.pdf.numPages;
        layout();
        // Jump to the (first) signed page so the stamp is visible straight away.
        if (job.first_signed_page && job.first_signed_page > 1) setTimeout(() => scrollToPage(job.first_signed_page, false), 50);
      } catch (ex) {
        message(ex.message || "Could not show the signed PDF.", "text-red-700");
      }
    }

    modal.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", close));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && isOpen()) close(); });
    $("#signed-goto").addEventListener("submit", (e) => { e.preventDefault(); scrollToPage(+pageInput.value, true); pageInput.blur(); });
    pageInput.addEventListener("change", () => scrollToPage(+pageInput.value, true));
    $("#signed-zoom-in").addEventListener("click", () => { v.zoom = nextZoom(v.zoom || fitScale(), +1); layout(v.current); });
    $("#signed-zoom-out").addEventListener("click", () => { v.zoom = nextZoom(v.zoom || fitScale(), -1); layout(v.current); });
    $("#signed-zoom-fit").addEventListener("click", () => { v.zoom = null; layout(v.current); });
    let rt; window.addEventListener("resize", () => { if (isOpen() && !v.zoom) { clearTimeout(rt); rt = setTimeout(() => layout(v.current), 200); } });

    return { open, close, isOpen };
  }

  // ================================================================== ADMIN
  function initAdmin() {
    bindLogout();
    const flash = $("#flash");
    const ok = (m) => { try { sessionStorage.setItem("flash", m); } catch (_) {} window.location.reload(); };
    const fail = (m) => { showMsg(flash, m, "error"); window.scrollTo({ top: 0, behavior: "smooth" }); };
    try { const m = sessionStorage.getItem("flash"); if (m) { showMsg(flash, m, "ok"); sessionStorage.removeItem("flash"); } } catch (_) {}

    $$("[data-action]").forEach((btn) => btn.addEventListener("click", async () => {
      if (btn.dataset.confirm && !confirm(btn.dataset.confirm)) return;
      btn.disabled = true;
      try { await api(btn.dataset.url, { method: btn.dataset.method || "POST", body: {} }); ok("Done."); }
      catch (ex) { btn.disabled = false; fail(ex.message); }
    }));

    $("#new-user-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        await api("/admin/api/users", { body: {
          username: f.username.value.trim(), password: f.password.value, full_name: f.full_name.value.trim(),
          allowed_ip: f.allowed_ip.value.trim(), is_admin: f.is_admin.checked, enforce_device_lock: f.enforce_device_lock.checked,
        } });
        ok(`User ${f.username.value.trim()} created.`);
      } catch (ex) { fail(ex.message); }
    });

    $$(".js-active").forEach((cb) => cb.addEventListener("change", async () => {
      try { await api(`/admin/api/users/${cb.dataset.id}/active`, { body: { is_active: cb.checked } }); ok(cb.checked ? "User enabled." : "User disabled and logged out."); }
      catch (ex) { cb.checked = !cb.checked; fail(ex.message); }
    }));

    $$(".js-toggle-edit").forEach((b) => b.addEventListener("click", () => $("#edit-" + b.dataset.id).classList.toggle("hidden")));

    $$(".js-edit-form").forEach((f) => f.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await api(`/admin/api/users/${f.dataset.id}/update`, { body: {
          full_name: f.full_name.value.trim(), allowed_ip: f.allowed_ip.value.trim(),
          is_admin: f.is_admin.checked, enforce_device_lock: f.enforce_device_lock.checked,
        } });
        ok("User updated.");
      } catch (ex) { fail(ex.message); }
    }));

    $$(".js-reset-pw").forEach((b) => b.addEventListener("click", async () => {
      const pw = prompt(`New password for ${b.dataset.name} (min 8 characters):`);
      if (!pw) return;
      try { await api(`/admin/api/users/${b.dataset.id}/password`, { body: { password: pw } }); ok("Password reset. The user's sessions were ended."); }
      catch (ex) { fail(ex.message); }
    }));

    $("#ip-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { const r = await api("/admin/api/ips", { body: { cidr: f.cidr.value.trim(), note: f.note.value.trim() } }); ok(`${r.cidr} whitelisted.`); }
      catch (ex) { fail(ex.message); }
    });

    $$(".js-whitelist-ip").forEach((b) => b.addEventListener("click", async () => {
      if (!confirm(`Whitelist ${b.dataset.ip}?`)) return;
      try { await api("/admin/api/ips", { body: { cidr: b.dataset.ip, note: "From audit log" } }); ok(`${b.dataset.ip} whitelisted.`); }
      catch (ex) { fail(ex.message); }
    }));

    const enf = $("#enforce-ip");
    enf.addEventListener("change", async () => {
      if (enf.checked && !confirm("Block every IP that is not on the whitelist?")) { enf.checked = false; return; }
      try { await api("/admin/api/settings/ip-whitelist", { body: { enabled: enf.checked } }); ok(enf.checked ? "IP whitelist enforced." : "IP whitelist no longer enforced."); }
      catch (ex) { enf.checked = !enf.checked; fail(ex.message); }
    });
  }

  window.DSC = { initLogin, initDashboard, initAdmin, api, fingerprint };
})();

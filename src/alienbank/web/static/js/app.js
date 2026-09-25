// AlienBank dashboard front-end.
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const fmt = (n) => new Intl.NumberFormat("en-KE", { minimumFractionDigits: 2 }).format(n);
// HTML-escape any server/tool-supplied string before interpolating into innerHTML.
// Account nicknames, transaction notes, counterparties and profile names are
// attacker-influenceable (transfer notes, teller_update_profile), so every
// dashboard render must escape them to avoid stored XSS.
const esc = (s) => String(s ?? "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

let showBalances = true;  // balances visible by default; user can hide them
let chatHistory = [];
let myAccounts = [];
let payeeOk = false; // has the destination been confirmed via name enquiry?
let selectedAccount = null; // account whose recent transactions are shown on the Account page

// Per-user preference: reveal the assistant's tool calls + tool responses.
const TOOLCALLS_KEY = `alienbank:showToolCalls:${(window.ALIENBANK || {}).username || "anon"}`;
let showToolCalls = localStorage.getItem(TOOLCALLS_KEY) === "1";

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  return res.json();
}

// ============ View switching ============
function showView(name) {
  $$(".view").forEach((v) => v.toggleAttribute("hidden", v.dataset.view !== name));
  $$(".nav-item[data-view]").forEach((n) =>
    n.classList.toggle("active", n.dataset.view === name)
  );
  if (name === "statement") loadStatement();
  if (name === "loans") loadLoans();
}

$$(".nav-item[data-view]").forEach((n) =>
  n.addEventListener("click", (e) => {
    e.preventDefault();
    showView(n.dataset.view);
  })
);

// ============ Account view ============
async function loadAccounts() {
  const data = await api("/api/accounts");
  myAccounts = Array.isArray(data) ? data : [];
  renderAccountCards();
  populateAccountSelects();
}

function renderAccountCards() {
  const wrap = $("#accountCards");
  if (!wrap) return;
  if (!myAccounts.length) {
    wrap.innerHTML = `<div class="loading">No accounts found.</div>`;
    if ($("#recentTxnBody")) $("#recentTxnBody").innerHTML = `<div class="empty">No accounts.</div>`;
    return;
  }
  // Default the recent-transactions panel to the first account (once).
  if (!selectedAccount || !myAccounts.some((a) => a.account_number === selectedAccount)) {
    selectedAccount = myAccounts[0].account_number;
  }
  wrap.innerHTML = "";
  for (const a of myAccounts) {
    const card = document.createElement("button");
    card.className = "acct-card" + (showBalances ? "" : " hide")
      + (a.account_number === selectedAccount ? " selected" : "");
    card.innerHTML = `
      <div class="nick">${esc(a.nickname)}</div>
      <div class="bal">${fmt(a.balance)} ${esc(a.currency)}</div>
      <div class="no">${esc(a.account_number)} · ${esc(a.account_type)}</div>`;
    card.addEventListener("click", () => selectAccountCard(a.account_number));
    wrap.appendChild(card);
  }
  loadRecentTransactions(selectedAccount);
}

function selectAccountCard(acct) {
  selectedAccount = acct;
  $$(".acct-card").forEach((c) =>
    c.classList.toggle("selected", c.querySelector(".no")?.textContent.startsWith(acct))
  );
  loadRecentTransactions(acct);
}

async function loadRecentTransactions(acct) {
  const body = $("#recentTxnBody");
  const title = $("#recentTxnTitle");
  if (!body || !acct) return;
  const nick = (myAccounts.find((a) => a.account_number === acct) || {}).nickname || acct;
  if (title) title.textContent = `Recent transactions — ${nick}`;
  body.innerHTML = `<div class="loading">Loading…</div>`;
  const data = await api(`/api/accounts/${acct}/statement?limit=10`);
  if (data.error) {
    body.innerHTML = `<div class="empty">${esc(data.message)}</div>`;
    return;
  }
  const txns = data.transactions || [];
  body.innerHTML = txns.length
    ? renderTxnTable(txns)
    : `<div class="empty">This account has no transactions yet.</div>`;
}

async function loadRecipients() {
  const wrap = $("#recipientList");
  if (!wrap) return;
  const data = await api("/api/recent-recipients");
  if (!Array.isArray(data) || !data.length) {
    wrap.innerHTML = `<div class="empty">No recent recipients yet. Your last 3 payees will appear here.</div>`;
    return;
  }
  wrap.innerHTML = "";
  for (const r of data.slice(0, 3)) {
    const item = document.createElement("button");
    item.className = "recipient";
    item.innerHTML = `
      <div class="rcp-avatar">${esc(r.account_name.slice(0, 2).toUpperCase())}</div>
      <div class="rcp-meta">
        <div class="rcp-name">${esc(r.account_name)}</div>
        <div class="rcp-acct">${esc(r.account_number)}</div>
      </div>`;
    item.addEventListener("click", () => {
      showView("transfer");
      $("#toAccount").value = r.account_number;
      checkAccount();
    });
    wrap.appendChild(item);
  }
}

$("#toggleBalance")?.addEventListener("click", () => {
  showBalances = !showBalances;
  $("#toggleBalance").textContent = showBalances ? "Hide balances 🙈" : "Show balances 👁";
  $$(".acct-card").forEach((c) => c.classList.toggle("hide", !showBalances));
});

// ============ Statement view ============
function populateAccountSelects() {
  for (const id of ["#stmtAccount", "#fromAccount"]) {
    const sel = $(id);
    if (!sel) continue;
    const prev = sel.value;
    sel.innerHTML = "";
    for (const a of myAccounts) {
      const opt = document.createElement("option");
      opt.value = a.account_number;
      opt.textContent = `${a.nickname} — ${a.account_number}`;
      sel.appendChild(opt);
    }
    if (prev) sel.value = prev;
  }
  updateFromBalance();
}

// Statement pagination state: the full transaction list is fetched once, then
// sliced into pages of STMT_PAGE_SIZE and navigated with Prev/Next.
const STMT_PAGE_SIZE = 15;
let stmtTxns = [];
let stmtPage = 0;

async function loadStatement() {
  const acct = $("#stmtAccount")?.value;
  const body = $("#statementBody");
  if (!acct) {
    body.innerHTML = `<div class="empty">You have no accounts to show.</div>`;
    $("#statementPager")?.setAttribute("hidden", "");
    $("#statementCount").textContent = "";
    return;
  }
  body.innerHTML = `<div class="loading">Loading…</div>`;
  const data = await api(`/api/accounts/${acct}/statement`);
  if (data.error) {
    body.innerHTML = `<div class="empty">${esc(data.message)}</div>`;
    $("#statementPager")?.setAttribute("hidden", "");
    $("#statementCount").textContent = "";
    return;
  }
  stmtTxns = data.transactions || [];
  stmtPage = 0;
  if (!stmtTxns.length) {
    body.innerHTML = `<div class="empty">This account has no transactions yet.</div>`;
    $("#statementPager")?.setAttribute("hidden", "");
    $("#statementCount").textContent = "";
    return;
  }
  renderStatementPage();
}

function renderStatementPage() {
  const body = $("#statementBody");
  const total = stmtTxns.length;
  const pageCount = Math.ceil(total / STMT_PAGE_SIZE);
  stmtPage = Math.max(0, Math.min(stmtPage, pageCount - 1));
  const start = stmtPage * STMT_PAGE_SIZE;
  const slice = stmtTxns.slice(start, start + STMT_PAGE_SIZE);

  body.innerHTML = renderTxnTable(slice);

  const countEl = $("#statementCount");
  if (countEl) countEl.textContent = `${total} transaction${total === 1 ? "" : "s"}`;

  const pager = $("#statementPager");
  if (pageCount <= 1) {
    pager?.setAttribute("hidden", "");
    return;
  }
  pager?.removeAttribute("hidden");
  $("#stmtPageInfo").textContent =
    `Showing ${start + 1}–${start + slice.length} · Page ${stmtPage + 1} of ${pageCount}`;
  $("#stmtPrev").disabled = stmtPage === 0;
  $("#stmtNext").disabled = stmtPage >= pageCount - 1;
}

function renderTxnTable(txns) {
  const rows = txns
    .map((t) => {
      const credit = t.amount > 0;
      return `<tr>
        <td class="t-date">${esc(t.ts.slice(0, 10))}</td>
        <td class="t-desc">${esc(t.description)}${t.counterparty ? ` <span class="cp">· ${esc(t.counterparty)}</span>` : ""}</td>
        <td class="t-amt ${credit ? "credit" : "debit"}">${credit ? "+" : ""}${fmt(t.amount)}</td>
        <td class="t-bal">${fmt(t.balance)}</td>
      </tr>`;
    })
    .join("");
  return `<div class="txn-scroll"><table class="txn-table">
    <thead><tr><th>Date</th><th>Description</th><th class="t-amt">Amount</th><th class="t-bal">Balance</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

$("#stmtAccount")?.addEventListener("change", () => loadStatement());
$("#stmtPrev")?.addEventListener("click", () => { stmtPage--; renderStatementPage(); });
$("#stmtNext")?.addEventListener("click", () => { stmtPage++; renderStatementPage(); });

// ============ Transfer view ============
function updateFromBalance() {
  const box = $("#fromBalance");
  const sel = $("#fromAccount");
  if (!box || !sel) return;
  const acct = myAccounts.find((a) => a.account_number === sel.value);
  if (!acct) { box.setAttribute("hidden", ""); return; }
  box.removeAttribute("hidden");
  box.innerHTML = `Available balance: <strong>${fmt(acct.balance)} ${acct.currency}</strong>`;
}

function resetPayee() {
  payeeOk = false;
  const box = $("#payeeConfirm");
  if (box) { box.setAttribute("hidden", ""); box.textContent = ""; }
  $("#sendTransferBtn")?.setAttribute("disabled", "");
}

async function checkAccount() {
  const acct = $("#toAccount").value.trim();
  const box = $("#payeeConfirm");
  if (!acct) return;
  box.removeAttribute("hidden");
  box.className = "payee-confirm loading-box";
  box.textContent = "Checking account…";
  const data = await api(`/api/name-enquiry/${encodeURIComponent(acct)}`);
  if (data.error) {
    box.className = "payee-confirm bad";
    box.textContent = `❌ ${data.message}`;
    payeeOk = false;
    $("#sendTransferBtn").setAttribute("disabled", "");
    return;
  }
  box.className = "payee-confirm good";
  box.innerHTML = `✅ <strong>${esc(data.account_name)}</strong> · ${esc(data.account_number)}`;
  payeeOk = true;
  $("#sendTransferBtn").removeAttribute("disabled");
}

$("#checkAccountBtn")?.addEventListener("click", checkAccount);
$("#toAccount")?.addEventListener("input", resetPayee);
$("#fromAccount")?.addEventListener("change", updateFromBalance);

$("#sendTransferBtn")?.addEventListener("click", async () => {
  const box = $("#transferResult");
  const body = {
    from_account: $("#fromAccount").value,
    to_account: $("#toAccount").value.trim(),
    amount: parseFloat($("#transferAmount").value),
    note: $("#transferNote").value.trim(),
  };
  if (!payeeOk) return;
  if (!(body.amount > 0)) {
    box.removeAttribute("hidden");
    box.className = "transfer-result bad";
    box.textContent = "Enter a valid amount.";
    return;
  }
  $("#sendTransferBtn").setAttribute("disabled", "");
  const data = await api("/api/transfer", { method: "POST", body: JSON.stringify(body) });
  box.removeAttribute("hidden");
  if (data.error) {
    box.className = "transfer-result bad";
    box.textContent = `❌ ${data.message}`;
    $("#sendTransferBtn").removeAttribute("disabled");
    return;
  }
  box.className = "transfer-result good";
  box.innerHTML = `✅ Sent ${fmt(body.amount)} KES to ${esc(body.to_account)}.<br>New balance of ${esc(data.account_number)}: <strong>${fmt(data.balance)} KES</strong>`;
  $("#transferAmount").value = "";
  $("#transferNote").value = "";
  await loadAccounts();
  await loadRecipients();
  resetPayee();
});

// ============ Loans view ============
const trendMeta = {
  increasing: { icon: "📈", cls: "up", label: "Earnings increasing" },
  stable: { icon: "➖", cls: "flat", label: "Earnings stable" },
  declining: { icon: "📉", cls: "down", label: "Earnings declining" },
};

async function loadLoans() {
  populateLoanAccounts();
  await Promise.all([loadLoanLimit(), loadMyLoans()]);
}

function populateLoanAccounts() {
  const sel = $("#loanAccount");
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = "";
  for (const a of myAccounts) {
    const opt = document.createElement("option");
    opt.value = a.account_number;
    opt.textContent = `${a.nickname} — ${a.account_number}`;
    sel.appendChild(opt);
  }
  if (prev) sel.value = prev;
}

async function loadLoanLimit(refresh = false) {
  const card = $("#loanLimitCard");
  if (!card) return;
  card.innerHTML = `<div class="loading">${refresh ? "Re-analysing your statement…" : "Loading your loan limit…"}</div>`;
  const data = await api(`/api/loans/limit${refresh ? "?refresh=true" : ""}`);
  if (data.error) {
    card.innerHTML = `<div class="empty">${esc(data.message)}</div>`;
    return;
  }
  const t = trendMeta[data.trend] || trendMeta.stable;
  const validTo = String(data.expires_at || "").slice(0, 10);
  card.innerHTML = `
    <div class="loan-limit-head">
      <div>
        <div class="loan-limit-label">Your approved loan limit</div>
        <div class="loan-limit-amount">${fmt(data.limit)} <span>KES</span></div>
      </div>
      <span class="trend-chip ${t.cls}" title="${esc(t.label)}">${t.icon} ${esc(data.trend)}</span>
    </div>
    <div class="loan-limit-meta">
      <div><span>Recommended</span><strong>${fmt(data.recommended)} KES</strong></div>
      <div><span>Affordable monthly repayment</span><strong>${fmt(data.monthly_repayment)} KES</strong></div>
    </div>
    <div class="loan-rationale">${esc(data.rationale)}</div>
    <div class="loan-limit-foot">
      <span class="muted">Based on your statement · valid to ${esc(validTo)}</span>
      <button class="link" id="refreshLimitBtn" title="Force a fresh analysis">↻ Re-analyse</button>
    </div>`;
  $("#refreshLimitBtn")?.addEventListener("click", () => loadLoanLimit(true));
}

async function loadMyLoans() {
  const body = $("#myLoansBody");
  if (!body) return;
  body.innerHTML = `<div class="loading">Loading…</div>`;
  const data = await api("/api/loans");
  if (data.error) {
    body.innerHTML = `<div class="empty">${esc(data.message)}</div>`;
    return;
  }
  if (!Array.isArray(data) || !data.length) {
    body.innerHTML = `<div class="empty">You have no loans yet.</div>`;
    return;
  }
  body.innerHTML = data.map((l) => {
    const repaid = l.status === "repaid";
    return `<div class="loan-row">
      <div class="loan-row-main">
        <span class="loan-ref">${esc(l.reference)}</span>
        <span class="loan-status ${repaid ? "repaid" : "active"}">${repaid ? "repaid" : "active"}</span>
      </div>
      <div class="loan-row-figs">
        <span>Principal <strong>${fmt(l.principal)}</strong></span>
        <span>+12% charge <strong>${fmt(l.service_charge)}</strong></span>
        <span>Outstanding <strong>${fmt(l.outstanding)}</strong></span>
      </div>
      <div class="loan-row-actions">
        <button class="link loan-stmt-btn" data-ref="${esc(l.reference)}">📄 View statement</button>
      </div>
      <div class="loan-stmt" data-ref="${esc(l.reference)}" hidden></div>
      ${repaid ? "" : `<div class="loan-repay-row">
        <input type="number" min="1" step="0.01" placeholder="Repay amount" data-ref="${esc(l.reference)}" class="loan-repay-amt" />
        <button class="btn-outline loan-repay-btn" data-ref="${esc(l.reference)}" data-acct="${esc(l.account_number)}">Repay</button>
      </div>`}
    </div>`;
  }).join("");
  $$(".loan-repay-btn").forEach((btn) =>
    btn.addEventListener("click", () => repayLoan(btn.dataset.ref, btn.dataset.acct))
  );
  $$(".loan-stmt-btn").forEach((btn) =>
    btn.addEventListener("click", () => toggleLoanStatement(btn.dataset.ref, btn))
  );
}

async function toggleLoanStatement(reference, btn) {
  const panel = document.querySelector(`.loan-stmt[data-ref="${reference}"]`);
  if (!panel) return;
  if (!panel.hasAttribute("hidden")) {
    panel.setAttribute("hidden", "");
    btn.textContent = "📄 View statement";
    return;
  }
  btn.textContent = "▲ Hide statement";
  panel.removeAttribute("hidden");
  panel.innerHTML = `<div class="loading">Loading statement…</div>`;
  const data = await api(`/api/loans/${encodeURIComponent(reference)}/statement`);
  if (data.error) {
    panel.innerHTML = `<div class="empty">${esc(data.message)}</div>`;
    return;
  }
  // Disbursement and the service charge both increase what is owed (shown +);
  // repayments reduce it (shown −).
  const kindLabel = { disbursement: "Disbursement", service_charge: "Service charge (12%)", repayment: "Repayment" };
  const rows = (data.payments || []).map((p) => {
    const adds = p.kind !== "repayment";
    return `<tr>
      <td class="t-date">${esc(String(p.ts).slice(0, 10))}</td>
      <td class="t-desc">${esc(kindLabel[p.kind] || p.kind)}${p.note ? ` <span class="cp">· ${esc(p.note)}</span>` : ""}</td>
      <td class="t-amt ${adds ? "credit" : "debit"}">${adds ? "+" : "−"}${fmt(p.amount)}</td>
      <td class="t-bal">${fmt(p.outstanding)}</td>
    </tr>`;
  }).join("");
  panel.innerHTML = `
    <div class="loan-stmt-sum">
      <span>Principal <strong>${fmt(data.loan.principal)}</strong></span>
      <span>Service charge <strong>${fmt(data.loan.service_charge)}</strong></span>
      <span>Total repayable <strong>${fmt(data.loan.total_repayable)}</strong></span>
      <span>Total repaid <strong>${fmt(data.total_repaid)}</strong></span>
      <span>Outstanding <strong>${fmt(data.loan.outstanding)}</strong></span>
    </div>
    <div class="txn-scroll"><table class="txn-table">
      <thead><tr><th>Date</th><th>Movement</th><th class="t-amt">Amount</th><th class="t-bal">Outstanding</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
}

async function repayLoan(reference, account_number) {
  const input = document.querySelector(`.loan-repay-amt[data-ref="${reference}"]`);
  const amount = parseFloat(input?.value);
  if (!(amount > 0)) { alert("Enter a valid repayment amount."); return; }
  const data = await api("/api/loans/repay", {
    method: "POST",
    body: JSON.stringify({ reference, amount, account_number }),
  });
  if (data.error) { alert(`❌ ${data.message}`); return; }
  await Promise.all([loadMyLoans(), loadLoanLimit(), loadAccounts()]);
}

$("#applyLoanBtn")?.addEventListener("click", async () => {
  const box = $("#loanApplyResult");
  const body = {
    account_number: $("#loanAccount").value,
    amount: parseFloat($("#loanAmount").value),
    note: $("#loanNote").value.trim(),
  };
  if (!(body.amount > 0)) {
    box.removeAttribute("hidden");
    box.className = "transfer-result bad";
    box.textContent = "Enter a valid amount.";
    return;
  }
  $("#applyLoanBtn").setAttribute("disabled", "");
  const data = await api("/api/loans/apply", { method: "POST", body: JSON.stringify(body) });
  $("#applyLoanBtn").removeAttribute("disabled");
  box.removeAttribute("hidden");
  if (data.error) {
    box.className = "transfer-result bad";
    box.textContent = `❌ ${data.message}`;
    return;
  }
  box.className = "transfer-result good";
  box.innerHTML = `✅ Loan ${esc(data.reference)} — ${fmt(data.principal)} KES disbursed to ${esc(data.account_number)}.<br>`
    + `Plus 12% service charge ${fmt(data.service_charge)} KES · <strong>total repayable ${fmt(data.total_repayable)} KES</strong>.`;
  $("#loanAmount").value = "";
  $("#loanNote").value = "";
  updateLoanChargePreview();
  await Promise.all([loadMyLoans(), loadLoanLimit(), loadAccounts()]);
});

// Live preview of the 12% service charge as the customer types an amount.
const LOAN_SERVICE_CHARGE_RATE = 0.12;
function updateLoanChargePreview() {
  const box = $("#loanChargePreview");
  if (!box) return;
  const amt = parseFloat($("#loanAmount")?.value);
  if (!(amt > 0)) { box.setAttribute("hidden", ""); box.textContent = ""; return; }
  const charge = amt * LOAN_SERVICE_CHARGE_RATE;
  box.removeAttribute("hidden");
  box.innerHTML = `12% service charge: <strong>${fmt(charge)} KES</strong> · total repayable <strong>${fmt(amt + charge)} KES</strong>`;
}
$("#loanAmount")?.addEventListener("input", updateLoanChargePreview);

// ============ Teller tools ============
$("#lookupBtn")?.addEventListener("click", async () => {
  const u = $("#lookupUser").value.trim();
  const data = await api(`/api/teller/customer/${encodeURIComponent(u)}/accounts`);
  $("#lookupOut").textContent = JSON.stringify(data, null, 2);
});
$("#depBtn")?.addEventListener("click", async () => {
  const body = { account_number: $("#depAcct").value.trim(), amount: parseFloat($("#depAmt").value) };
  const data = await api("/api/teller/deposit", { method: "POST", body: JSON.stringify(body) });
  $("#depOut").textContent = JSON.stringify(data, null, 2);
  loadAccounts();
});

// ============ Assistant (floating chat widget) ============
const chatPanel = $("#chatPanel");
const chatFab = $("#chatFab");

function openChat() {
  chatPanel.removeAttribute("hidden");
  chatFab.setAttribute("hidden", "");
  $("#chatText").focus();
}
function closeChat() {
  chatPanel.setAttribute("hidden", "");
  chatFab.removeAttribute("hidden");
}
chatFab.addEventListener("click", openChat);
$("#chatClose").addEventListener("click", closeChat);
// The left-nav Assistant item opens the same floating window.
$("#navAssistant")?.addEventListener("click", (e) => { e.preventDefault(); openChat(); });

// --- Enlarge / shrink (steps the panel size, clamped to the viewport) ---
function resizePanel(dw, dh) {
  const rect = chatPanel.getBoundingClientRect();
  const w = Math.min(window.innerWidth - 20, Math.max(320, rect.width + dw));
  const h = Math.min(window.innerHeight - 20, Math.max(360, rect.height + dh));
  chatPanel.style.width = w + "px";
  chatPanel.style.height = h + "px";
}
$("#chatBigger").addEventListener("click", () => resizePanel(120, 100));
$("#chatSmaller").addEventListener("click", () => resizePanel(-120, -100));

// --- Drag by the header ---
(function enableDrag() {
  const head = $("#chatHead");
  let dragging = false, sx = 0, sy = 0, sl = 0, st = 0;
  head.addEventListener("mousedown", (e) => {
    if (e.target.closest(".chat-icon")) return; // don't drag when hitting a button
    dragging = true;
    const rect = chatPanel.getBoundingClientRect();
    // switch from right/bottom anchoring to explicit left/top for dragging
    chatPanel.style.left = rect.left + "px";
    chatPanel.style.top = rect.top + "px";
    chatPanel.style.right = "auto";
    chatPanel.style.bottom = "auto";
    sx = e.clientX; sy = e.clientY; sl = rect.left; st = rect.top;
    document.body.style.userSelect = "none";
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const nl = Math.min(window.innerWidth - 80, Math.max(0, sl + e.clientX - sx));
    const nt = Math.min(window.innerHeight - 40, Math.max(0, st + e.clientY - sy));
    chatPanel.style.left = nl + "px";
    chatPanel.style.top = nt + "px";
  });
  window.addEventListener("mouseup", () => {
    dragging = false;
    document.body.style.userSelect = "";
  });
})();

// --- Free-form resize via the bottom-right grip ---
(function enableResizeGrip() {
  const grip = $("#chatResize");
  let resizing = false, sx = 0, sy = 0, sw = 0, sh = 0;
  grip.addEventListener("mousedown", (e) => {
    resizing = true;
    const rect = chatPanel.getBoundingClientRect();
    sx = e.clientX; sy = e.clientY; sw = rect.width; sh = rect.height;
    document.body.style.userSelect = "none";
    e.preventDefault();
  });
  window.addEventListener("mousemove", (e) => {
    if (!resizing) return;
    const w = Math.min(window.innerWidth - 20, Math.max(320, sw + e.clientX - sx));
    const h = Math.min(window.innerHeight - 20, Math.max(360, sh + e.clientY - sy));
    chatPanel.style.width = w + "px";
    chatPanel.style.height = h + "px";
  });
  window.addEventListener("mouseup", () => {
    resizing = false;
    document.body.style.userSelect = "";
  });
})();

// Render the assistant's light markdown as natural text: **bold** becomes a
// real bold span, `code` becomes styled inline text, and other markers are
// stripped. Everything is HTML-escaped first so tool output can't inject markup.
// Line breaks/lists are preserved by the .msg { white-space: pre-wrap } rule.
function renderReply(text) {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return escaped
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")   // **bold**
    .replace(/(^|\s)\*(?!\s)([^*\n]+?)\*(?=\s|[.,!?)]|$)/g, "$1<em>$2</em>") // *italic*
    .replace(/`([^`]+?)`/g, "<code>$1</code>")           // `code`
    .replace(/^\s*#{1,6}\s+/gm, "");                     // drop heading markers
}

function addMsg(text, cls) {
  const log = $("#chatLog");
  const div = document.createElement("div");
  div.className = `msg ${cls}`;
  if (cls === "bot" && text !== "…") {
    div.innerHTML = renderReply(text);
  } else {
    div.textContent = text;
  }
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}

// Pretty-print a tool argument/response JSON string; fall back to raw text.
function prettyJson(str) {
  if (str == null || str === "") return "";
  try { return JSON.stringify(JSON.parse(str), null, 2); }
  catch (_) { return String(str); }
}

// Render the assistant's tool calls (name + arguments + tool response) as a
// distinct block in the transcript. Shown only when the profile toggle is on.
function addToolCalls(calls) {
  if (!showToolCalls || !Array.isArray(calls) || !calls.length) return;
  const log = $("#chatLog");
  const wrap = document.createElement("div");
  wrap.className = "toolcalls";
  wrap.innerHTML =
    `<div class="tc-head">🛠 ${calls.length} tool call${calls.length > 1 ? "s" : ""}</div>` +
    calls.map((c) => `
      <div class="tc">
        <div class="tc-name">${esc(c.name)}</div>
        <div class="tc-row"><span class="tc-k">args</span><pre>${esc(prettyJson(c.arguments))}</pre></div>
        <div class="tc-row"><span class="tc-k">response</span><pre>${esc(prettyJson(c.output))}</pre></div>
      </div>`).join("");
  log.appendChild(wrap);
  log.scrollTop = log.scrollHeight;
}

// Render guardrail decisions (D1/D2/D3) as a compact chain, always shown so the
// user can see which layer fired at the current level.
function addGuardrails(decisions) {
  if (!Array.isArray(decisions) || !decisions.length) return;
  const log = $("#chatLog");
  const wrap = document.createElement("div");
  wrap.className = "guardrails";
  wrap.innerHTML =
    `<div class="gr-head">🛡 Guardrails</div>` +
    decisions.map((d) => `
      <div class="gr ${d.blocked ? "blocked" : "passed"}">
        <span class="gr-layer">${esc(d.layer)}</span>
        <span class="gr-name">${esc(d.name)}</span>
        <span class="gr-verdict">${d.blocked ? "⛔ blocked" : "✓ passed"}</span>
        ${d.detail ? `<span class="gr-detail">${esc(d.detail)}</span>` : ""}
      </div>`).join("");
  log.appendChild(wrap);
  log.scrollTop = log.scrollHeight;
}

async function sendChat() {
  const input = $("#chatText");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  addMsg(text, "user");
  const typing = addMsg("…", "bot");
  typing.classList.add("typing");
  try {
    const data = await api("/api/chat", {
      method: "POST",
      body: JSON.stringify({ message: text, history: chatHistory }),
    });
    typing.remove();
    addGuardrails(data.guardrails);
    addToolCalls(data.tool_calls);
    addMsg(data.reply || "(no response)", "bot");
    if (Array.isArray(data.history)) chatHistory = data.history;
    loadAccounts();
  } catch (err) {
    typing.remove();
    addMsg("Network error talking to the assistant.", "bot");
  }
}

$("#chatForm").addEventListener("submit", (e) => { e.preventDefault(); sendChat(); });
// Enter sends; Shift+Enter inserts a newline.
$("#chatText").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
});

// ============ Profile menu (holds the toggle + sign out) ============
const profileToggle = $("#profileToggle");
const profileMenu = $("#profileMenu");
if (profileToggle && profileMenu) {
  profileToggle.addEventListener("click", () => {
    const open = profileMenu.hasAttribute("hidden");
    profileMenu.toggleAttribute("hidden", !open);
    profileToggle.setAttribute("aria-expanded", String(open));
    profileToggle.classList.toggle("open", open);
  });
}

// ============ Profile setting: show tool calls ============
const toolToggle = $("#showToolCalls");
if (toolToggle) {
  toolToggle.checked = showToolCalls;
  toolToggle.addEventListener("change", () => {
    showToolCalls = toolToggle.checked;
    localStorage.setItem(TOOLCALLS_KEY, showToolCalls ? "1" : "0");
  });
}

// ============ Reset demo data ============
const resetBtn = $("#resetDbBtn");
if (resetBtn) {
  resetBtn.addEventListener("click", async () => {
    if (!confirm("Reset all AlienBank data back to the seeded demo dataset? This wipes every change you've made.")) return;
    const original = resetBtn.textContent;
    resetBtn.textContent = "Resetting…";
    resetBtn.disabled = true;
    try {
      const data = await api("/api/reset", { method: "POST" });
      if (data.status === "ok") {
        chatHistory = [];
        // Reload so every view reflects the fresh dataset.
        location.reload();
      } else {
        resetBtn.textContent = original;
        resetBtn.disabled = false;
        alert("Reset failed.");
      }
    } catch (_) {
      resetBtn.textContent = original;
      resetBtn.disabled = false;
      alert("Reset failed (network error).");
    }
  });
}

// ============ Security level selector ============
const levelSelect = $("#levelSelect");
const levelTagline = $("#levelTagline");
const levelBadge = $("#levelBadge");
const LEVELS = (window.ALIENBANK || {}).levels || [];

function levelInfo(lv) {
  return LEVELS.find((x) => x.level === lv) || { name: "", tagline: "" };
}
function paintLevel(lv) {
  const info = levelInfo(lv);
  if (levelTagline) levelTagline.textContent = info.tagline || "";
  if (levelBadge) levelBadge.textContent = `L${lv} · ${info.name}`;
}

if (levelSelect) {
  paintLevel(parseInt(levelSelect.value, 10));
  levelSelect.addEventListener("change", async () => {
    const lv = parseInt(levelSelect.value, 10);
    const data = await api("/api/level", { method: "POST", body: JSON.stringify({ level: lv }) });
    paintLevel(data.level);
    // New level = fresh challenge: clear the conversation context.
    chatHistory = [];
    const log = $("#chatLog");
    if (log) log.innerHTML = `<div class="msg bot">Security level set to L${data.level} — ${data.name}. ${data.tagline}</div>`;
  });
}

// ============ Init ============
(async function init() {
  await loadAccounts();
  await loadRecipients();
})();

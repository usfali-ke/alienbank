"""SQLite storage + schema + seed data for AlienBank."""
from __future__ import annotations

import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password      TEXT NOT NULL,            -- plaintext: this is a lab, not prod
    full_name     TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('customer', 'teller')),
    email         TEXT,
    phone         TEXT,
    -- Random, non-identifying per-user pseudonym used as the correlation handle
    -- in security logs (actor.ref). It carries no PII and reveals no ordering or
    -- user count; re-identification (pseudonym -> username) is a privileged,
    -- audited app-side lookup, kept out of the logs. See SECURITY_LOGGING_PLAN.md.
    pseudonym     TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS accounts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT UNIQUE NOT NULL,
    owner_id       INTEGER NOT NULL REFERENCES users(id),
    nickname       TEXT NOT NULL,
    account_type   TEXT NOT NULL,
    balance_cents  INTEGER NOT NULL DEFAULT 0,
    currency       TEXT NOT NULL DEFAULT 'KES'
);

CREATE TABLE IF NOT EXISTS transactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT NOT NULL REFERENCES accounts(account_number),
    ts             TEXT NOT NULL,
    amount_cents   INTEGER NOT NULL,        -- signed: credit +, debit -
    balance_cents  INTEGER NOT NULL,        -- running balance after txn
    description    TEXT NOT NULL,
    counterparty   TEXT
);

-- Cached loan eligibility from the LLM statement analysis. One live row per
-- customer: computed once, then reused until it expires (10 days). Storing the
-- computed limit is a deliberate lab surface — a learner who can bypass the
-- ownership check can overwrite someone's limit (or inflate their own).
CREATE TABLE IF NOT EXISTS loan_limits (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL REFERENCES users(username),
    limit_cents      INTEGER NOT NULL,        -- max principal the customer may borrow
    recommended_cents INTEGER NOT NULL,       -- LLM-suggested affordable principal
    monthly_repayment_cents INTEGER NOT NULL, -- affordable monthly repayment
    trend            TEXT NOT NULL,           -- 'increasing' | 'stable' | 'declining'
    rationale        TEXT NOT NULL,           -- LLM's human-readable justification
    computed_at      TEXT NOT NULL,           -- ISO ts the analysis ran
    expires_at       TEXT NOT NULL            -- computed_at + 10 days
);

-- Disbursed loans. A loan credits the customer's account and is repaid from it.
CREATE TABLE IF NOT EXISTS loans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    reference        TEXT UNIQUE NOT NULL,    -- human-facing loan id, e.g. LN-0001
    username         TEXT NOT NULL REFERENCES users(username),
    account_number   TEXT NOT NULL REFERENCES accounts(account_number),  -- disbursed to / repaid from
    principal_cents  INTEGER NOT NULL,        -- amount borrowed (disbursed to the account)
    service_charge_cents INTEGER NOT NULL DEFAULT 0,  -- 12% service charge added on top
    outstanding_cents INTEGER NOT NULL,       -- remaining balance owed (principal + charge - repaid)
    status           TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'repaid'
    opened_at        TEXT NOT NULL,
    note             TEXT
);

-- Per-loan ledger: one row per movement (disbursement, the service charge, then
-- each repayment), with the running outstanding after the event. Backs the loan
-- statement, kept separate from the account transaction ledger so it is
-- unambiguous regardless of any custom disbursement note.
CREATE TABLE IF NOT EXISTS loan_payments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    loan_reference   TEXT NOT NULL REFERENCES loans(reference),
    ts               TEXT NOT NULL,
    kind             TEXT NOT NULL,           -- 'disbursement' | 'service_charge' | 'repayment'
    amount_cents     INTEGER NOT NULL,        -- positive magnitude of the movement
    outstanding_cents INTEGER NOT NULL,       -- loan balance owed AFTER this event
    note             TEXT
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_pseudonym() -> str:
    """A random 128-bit correlation handle for security logs (actor.ref).

    Stored, not derived — so there is no salt/key to manage or leak. Carries no
    PII and no ordering, so it cannot be reversed from a log alone.
    """
    return secrets.token_hex(16)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Seed data — the canonical dataset. Loaded on first setup and used to rebuild
# the database on an explicit reset. (Restarts never reset: init_db only seeds
# when the DB is empty.)
# ---------------------------------------------------------------------------
_SEED_USERS = [
    # username, password, full_name, role, email, phone
    ("ana", "ana123", "Ana Mueli", "customer", "ana@example.com", "+254700000001"),
    ("duncan", "duncan123", "Duncan Otieno", "customer", "duncan@example.com", "+254700000002"),
    ("brenda", "brenda123", "Brenda Wambui", "customer", "brenda@example.com", "+254700000003"),
    ("kevin", "kevin123", "Kevin Mwangi", "customer", "kevin@example.com", "+254700000004"),
    ("fatima", "fatima123", "Fatima Noor", "customer", "fatima@example.com", "+254700000005"),
    ("teller", "teller123", "Tom Teller", "teller", "tom@alienbank.example", "+254700000009"),
    ("mary", "mary123", "Mary Achieng", "teller", "mary@alienbank.example", "+254700000010"),
]

# account_number, owner_username, nickname, type, opening balance (KES)
_SEED_ACCOUNTS = [
    ("0101700001", "ana", "Wedding savings", "Savings", 30_000.00),
    ("0101700002", "ana", "My account", "Current", 45_000.00),
    ("0101700003", "ana", "Duncan & Ana", "Joint", 20_000.00),
    ("0202700010", "duncan", "Duncan main", "Current", 12_000.00),
    ("0202700011", "duncan", "Duncan savings", "Savings", 60_000.00),
    ("0303700020", "brenda", "Brenda savings", "Savings", 85_000.00),
    ("0404700030", "kevin", "Kevin current", "Current", 8_500.00),
    ("0505700040", "fatima", "Fatima business", "Current", 240_000.00),
    ("0505700041", "fatima", "Fatima savings", "Savings", 120_000.00),
]

# Per-account activity applied AFTER the opening balance, oldest first (days_ago
# decreasing). Each is (days_ago, amount KES [+credit / -debit], description,
# counterparty|None). Running balances are computed so the ledger stays
# internally consistent, and balances are designed never to go negative.
_SEED_ACTIVITY = {
    # Ana — current account (primary demo account): 33 transactions.
    "0101700002": [
        (34, 85_000.00, "Salary — June", None),
        (34, -12_000.00, "Rent — landlord", None),
        (33, -2_500.00, "Naivas Supermarket", None),
        (33, -1_499.00, "Netflix", None),
        (32, -3_000.00, "KPLC electricity tokens", None),
        (31, -1_200.00, "Java House", None),
        (30, -900.00, "Uber", None),
        (29, -2_300.00, "Carrefour", None),
        (28, -1_500.00, "Safaricom airtime", None),
        (27, -4_500.00, "Fuel — Shell", None),
        (26, -800.00, "M-Pesa withdrawal", None),
        (25, -2_100.00, "DSTV subscription", None),
        (24, -1_750.00, "Pharmacy", None),
        (23, -5_000.00, "Transfer to Wedding savings", "0101700001"),
        (22, 3_000.00, "Refund — Jumia", None),
        (21, -3_600.00, "Naivas Supermarket", None),
        (20, -1_200.00, "Java House", None),
        (19, -2_000.00, "Glovo food delivery", None),
        (18, -1_500.00, "Bolt", None),
        (17, -2_800.00, "Sarit Centre", None),
        (16, -1_000.00, "Safaricom airtime", None),
        (15, -6_500.00, "Fuel & car service", None),
        (14, -1_200.00, "Chemist", None),
        (13, -3_500.00, "Naivas Supermarket", None),
        (12, -900.00, "Uber", None),
        (10, -2_500.00, "Restaurant — CJ's", None),
        (8, -1_800.00, "Cinema & dinner", None),
        (6, 85_000.00, "Salary — July", None),
        (5, -12_000.00, "Rent — landlord", None),
        (4, -3_600.00, "Naivas Supermarket", None),
        (3, -1_499.00, "Netflix", None),
        (2, -2_200.00, "KPLC tokens", None),
        (1, -1_200.00, "Java House", None),
    ],
    # Ana — wedding savings: 32 transactions.
    "0101700001": [
        (34, 10_000.00, "Standing order — savings", None),
        (33, 2_500.00, "Interest credit", None),
        (32, 5_000.00, "Transfer from My account", "0101700002"),
        (31, 3_000.00, "M-Pesa top-up", None),
        (30, 10_000.00, "Standing order — savings", None),
        (29, -2_000.00, "Bank charges", None),
        (28, 1_500.00, "Interest credit", None),
        (27, 4_000.00, "Gift deposit", None),
        (26, 10_000.00, "Standing order — savings", None),
        (25, -8_000.00, "Withdrawal — venue deposit", None),
        (24, 2_000.00, "Interest credit", None),
        (23, 3_000.00, "M-Pesa top-up", None),
        (22, 10_000.00, "Standing order — savings", None),
        (21, -1_500.00, "Service fee", None),
        (20, 2_500.00, "Interest credit", None),
        (19, 5_000.00, "Transfer from My account", "0101700002"),
        (18, 10_000.00, "Standing order — savings", None),
        (17, -5_000.00, "Withdrawal — supplier deposit", None),
        (16, 1_500.00, "Interest credit", None),
        (15, 3_000.00, "M-Pesa top-up", None),
        (14, 10_000.00, "Standing order — savings", None),
        (13, -2_000.00, "Withdrawal", None),
        (12, 2_500.00, "Interest credit", None),
        (11, 4_000.00, "Gift deposit", None),
        (10, 10_000.00, "Standing order — savings", None),
        (9, -8_000.00, "Withdrawal — florist deposit", None),
        (8, 2_000.00, "Interest credit", None),
        (7, 3_000.00, "M-Pesa top-up", None),
        (6, 10_000.00, "Standing order — savings", None),
        (5, -3_000.00, "Withdrawal", None),
        (3, 2_500.00, "Interest credit", None),
        (2, 10_000.00, "Standing order — savings", None),
    ],
    # Ana & Duncan — joint account: 32 transactions.
    "0101700003": [
        (34, 15_000.00, "Joint top-up — Duncan", None),
        (33, 8_000.00, "Joint top-up — Ana", None),
        (32, -6_000.00, "Groceries", None),
        (31, -4_500.00, "Utilities", None),
        (30, -2_000.00, "Internet — Zuku", None),
        (29, -3_000.00, "DStv", None),
        (28, 15_000.00, "Joint top-up — Duncan", None),
        (27, -5_000.00, "Groceries — Carrefour", None),
        (26, -1_800.00, "Water bill", None),
        (25, -2_500.00, "House help salary", None),
        (24, -1_200.00, "Gas refill", None),
        (23, 8_000.00, "Joint top-up — Ana", None),
        (22, -3_500.00, "Groceries", None),
        (21, -2_000.00, "Electricity tokens", None),
        (20, -4_500.00, "Utilities", None),
        (19, -1_500.00, "Cleaning supplies", None),
        (18, 15_000.00, "Joint top-up — Duncan", None),
        (17, -6_000.00, "Groceries", None),
        (16, -2_500.00, "House help salary", None),
        (15, -1_800.00, "Internet — Zuku", None),
        (14, -3_000.00, "DStv", None),
        (13, 8_000.00, "Joint top-up — Ana", None),
        (12, -2_000.00, "Water bill", None),
        (11, -4_000.00, "Groceries", None),
        (10, -1_200.00, "Gas refill", None),
        (9, -2_500.00, "House help salary", None),
        (8, 15_000.00, "Joint top-up — Duncan", None),
        (7, -5_500.00, "Groceries — Naivas", None),
        (6, -2_000.00, "Electricity tokens", None),
        (5, -3_000.00, "Dinner out", None),
        (4, -1_500.00, "Pharmacy", None),
        (2, 8_000.00, "Joint top-up — Ana", None),
    ],
    # Duncan — current account: 33 transactions.
    "0202700010": [
        (34, 55_000.00, "Salary", None),
        (34, -15_000.00, "Rent", None),
        (33, -3_200.00, "Naivas Supermarket", None),
        (32, -2_000.00, "Airtime & data", None),
        (31, -4_000.00, "Fuel — Total", None),
        (30, -1_099.00, "Netflix", None),
        (29, -2_500.00, "Nyama Mama", None),
        (28, -3_000.00, "Sarit Centre", None),
        (27, -1_500.00, "Pharmacy", None),
        (26, -2_200.00, "KPLC tokens", None),
        (25, -800.00, "Uber", None),
        (24, 6_000.00, "Refund — supplier", None),
        (23, -3_500.00, "School fees", None),
        (22, -1_200.00, "Carrefour", None),
        (21, -2_000.00, "Java House", None),
        (20, -1_800.00, "Bolt rides", None),
        (19, -900.00, "Airtime", None),
        (18, -2_500.00, "Dinner — Talisman", None),
        (17, -4_000.00, "Fuel", None),
        (16, -1_500.00, "Groceries", None),
        (15, -2_000.00, "Gym membership", None),
        (14, -1_200.00, "Pharmacy", None),
        (13, -3_000.00, "Shopping — Two Rivers", None),
        (12, -1_000.00, "Uber", None),
        (11, 2_000.00, "M-Pesa deposit", None),
        (10, -1_500.00, "Groceries", None),
        (8, 55_000.00, "Salary", None),
        (7, -15_000.00, "Rent", None),
        (6, -3_200.00, "Naivas Supermarket", None),
        (5, -2_000.00, "Airtime & data", None),
        (4, -4_000.00, "Fuel — Total", None),
        (2, -3_500.00, "School fees", None),
        (1, -1_200.00, "Carrefour", None),
    ],
    # Duncan — savings: 33 transactions.
    "0202700011": [
        (34, 10_000.00, "Standing order", None),
        (33, 1_800.00, "Interest credit", None),
        (32, 5_000.00, "M-Pesa top-up", None),
        (31, -15_000.00, "Withdrawal", None),
        (30, 10_000.00, "Standing order", None),
        (29, 2_000.00, "Interest credit", None),
        (28, -3_000.00, "Withdrawal", None),
        (27, 4_000.00, "Bonus saving", None),
        (26, 10_000.00, "Standing order", None),
        (25, -5_000.00, "Withdrawal", None),
        (24, 1_800.00, "Interest credit", None),
        (23, 3_000.00, "M-Pesa top-up", None),
        (22, 10_000.00, "Standing order", None),
        (21, -8_000.00, "Withdrawal — car repair", None),
        (20, 2_000.00, "Interest credit", None),
        (19, -2_000.00, "Bank charges", None),
        (18, 10_000.00, "Standing order", None),
        (17, 5_000.00, "M-Pesa top-up", None),
        (16, -15_000.00, "Withdrawal", None),
        (15, 2_000.00, "Interest credit", None),
        (14, 10_000.00, "Standing order", None),
        (13, -4_000.00, "Withdrawal", None),
        (12, 3_000.00, "M-Pesa top-up", None),
        (11, 1_800.00, "Interest credit", None),
        (10, -6_000.00, "Withdrawal", None),
        (9, 10_000.00, "Standing order", None),
        (8, 2_000.00, "Interest credit", None),
        (7, -3_000.00, "Withdrawal", None),
        (6, 5_000.00, "M-Pesa top-up", None),
        (5, 10_000.00, "Standing order", None),
        (3, -5_000.00, "Withdrawal", None),
        (2, 2_000.00, "Interest credit", None),
        (1, 10_000.00, "Standing order", None),
    ],
    # Brenda — savings: 34 transactions.
    "0303700020": [
        (34, 20_000.00, "Deposit", None),
        (33, -2_500.00, "ATM withdrawal", None),
        (32, 3_000.00, "Interest credit", None),
        (31, -4_000.00, "School fees", None),
        (30, -1_800.00, "Supermarket", None),
        (29, -10_000.00, "Cash withdrawal", None),
        (28, 25_000.00, "Deposit — business", None),
        (27, -5_500.00, "Medical — clinic", None),
        (26, -3_200.00, "Groceries", None),
        (25, -1_500.00, "Airtime", None),
        (24, 3_000.00, "Refund — vendor", None),
        (23, -8_000.00, "Cash withdrawal", None),
        (22, -1_200.00, "Pharmacy", None),
        (21, 2_000.00, "Interest credit", None),
        (20, -900.00, "Uber", None),
        (19, -2_400.00, "Carrefour", None),
        (18, -3_000.00, "Salon", None),
        (17, 15_000.00, "Deposit — business", None),
        (16, -5_000.00, "Cash withdrawal", None),
        (15, -2_200.00, "Groceries", None),
        (14, -1_500.00, "KPLC tokens", None),
        (13, -4_000.00, "School fees", None),
        (12, 3_000.00, "Interest credit", None),
        (11, -1_800.00, "Supermarket", None),
        (10, -2_500.00, "Restaurant", None),
        (9, 3_000.00, "Refund — vendor", None),
        (8, -6_000.00, "Cash withdrawal", None),
        (7, -1_200.00, "Pharmacy", None),
        (6, 20_000.00, "Deposit — business", None),
        (5, -3_200.00, "Groceries", None),
        (4, -900.00, "Uber", None),
        (3, 2_000.00, "Interest credit", None),
        (2, -2_400.00, "Carrefour", None),
        (1, -1_500.00, "Airtime", None),
    ],
    # Kevin — current account: 34 transactions.
    "0404700030": [
        (34, 9_000.00, "Casual gig", None),
        (33, -3_500.00, "Rent", None),
        (32, -800.00, "M-Pesa withdrawal", None),
        (31, -1_200.00, "Groceries", None),
        (30, 4_000.00, "Freelance", None),
        (29, -600.00, "Airtime", None),
        (28, -1_500.00, "Fuel", None),
        (27, -900.00, "Restaurant", None),
        (26, 6_000.00, "Casual gig", None),
        (25, -1_100.00, "Shopping", None),
        (24, -700.00, "Uber", None),
        (23, 2_500.00, "Refund", None),
        (22, -1_300.00, "Pharmacy", None),
        (21, -900.00, "Groceries", None),
        (20, 5_000.00, "Freelance project", None),
        (19, -3_500.00, "Rent", None),
        (18, -800.00, "Airtime & data", None),
        (17, -1_200.00, "Matatu & Bolt", None),
        (16, 3_000.00, "Casual gig", None),
        (15, -1_500.00, "Groceries", None),
        (14, -600.00, "M-Pesa withdrawal", None),
        (13, -900.00, "Restaurant", None),
        (12, 4_000.00, "Freelance", None),
        (11, -1_100.00, "Shopping", None),
        (10, -700.00, "Fuel", None),
        (9, -1_300.00, "Pharmacy", None),
        (8, 6_000.00, "Casual gig", None),
        (7, -3_500.00, "Rent", None),
        (6, -800.00, "Airtime", None),
        (5, -1_200.00, "Groceries", None),
        (4, 2_500.00, "Refund", None),
        (3, -900.00, "Uber", None),
        (2, -1_500.00, "Dinner", None),
        (1, -700.00, "M-Pesa withdrawal", None),
    ],
    # Fatima — business account: 34 transactions.
    "0505700040": [
        (34, 150_000.00, "Client invoice #2231", None),
        (33, -48_000.00, "Supplier payment", None),
        (32, -12_000.00, "Payroll — casual", None),
        (31, -25_000.00, "Rent — office", None),
        (30, -9_500.00, "Utilities", None),
        (29, 80_000.00, "Client invoice #2233", None),
        (28, -15_000.00, "Inventory restock", None),
        (27, -6_000.00, "Marketing — ads", None),
        (26, -3_500.00, "Bank charges", None),
        (25, -12_000.00, "Payroll — casual", None),
        (24, -18_000.00, "Equipment purchase", None),
        (23, 120_000.00, "Client invoice #2238", None),
        (22, -48_000.00, "Supplier payment", None),
        (21, -9_500.00, "Utilities", None),
        (20, -7_000.00, "Fuel — fleet", None),
        (19, -12_000.00, "Payroll — casual", None),
        (18, -25_000.00, "Rent — office", None),
        (17, -4_000.00, "Software subscriptions", None),
        (16, 30_000.00, "Client invoice #2240", None),
        (15, -15_000.00, "Inventory restock", None),
        (14, -6_000.00, "Marketing — ads", None),
        (13, -3_500.00, "Bank charges", None),
        (12, -12_000.00, "Payroll — casual", None),
        (11, 95_000.00, "Client invoice #2245", None),
        (10, -48_000.00, "Supplier payment", None),
        (9, -9_500.00, "Utilities", None),
        (8, -22_000.00, "Equipment lease", None),
        (7, -12_000.00, "Payroll — casual", None),
        (6, 60_000.00, "Client invoice #2250", None),
        (5, -25_000.00, "Rent — office", None),
        (4, -8_000.00, "Marketing — ads", None),
        (3, -15_000.00, "Inventory restock", None),
        (2, -12_000.00, "Payroll — casual", None),
        (1, -3_500.00, "Bank charges", None),
    ],
    # Fatima — savings: 34 transactions.
    "0505700041": [
        (34, 50_000.00, "Transfer from business", None),
        (33, 2_500.00, "Interest credit", None),
        (32, -30_000.00, "Withdrawal", None),
        (31, 5_000.00, "M-Pesa top-up", None),
        (30, 50_000.00, "Transfer from business", None),
        (29, 3_000.00, "Interest credit", None),
        (28, -20_000.00, "Withdrawal", None),
        (27, -5_000.00, "Investment — MMF", None),
        (26, 10_000.00, "Transfer from business", None),
        (25, 2_500.00, "Interest credit", None),
        (24, -15_000.00, "Withdrawal", None),
        (23, 50_000.00, "Transfer from business", None),
        (22, -30_000.00, "Withdrawal", None),
        (21, 3_000.00, "Interest credit", None),
        (20, -10_000.00, "Investment — MMF", None),
        (19, 5_000.00, "M-Pesa top-up", None),
        (18, -20_000.00, "Withdrawal", None),
        (17, 2_500.00, "Interest credit", None),
        (16, 50_000.00, "Transfer from business", None),
        (15, -25_000.00, "Withdrawal", None),
        (14, 3_000.00, "Interest credit", None),
        (13, -15_000.00, "Investment — MMF", None),
        (12, 10_000.00, "Transfer from business", None),
        (11, -20_000.00, "Withdrawal", None),
        (10, 2_500.00, "Interest credit", None),
        (9, 50_000.00, "Transfer from business", None),
        (8, -30_000.00, "Withdrawal", None),
        (7, 3_000.00, "Interest credit", None),
        (6, -10_000.00, "Investment — MMF", None),
        (5, 5_000.00, "M-Pesa top-up", None),
        (4, -20_000.00, "Withdrawal", None),
        (3, 2_500.00, "Interest credit", None),
        (2, 50_000.00, "Transfer from business", None),
        (1, -15_000.00, "Withdrawal", None),
    ],
}


def _ts_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _seed(conn: sqlite3.Connection) -> None:
    """Populate an empty schema with the canonical seed dataset."""
    for username, pw, name, role, email, phone in _SEED_USERS:
        conn.execute(
            "INSERT INTO users (username, password, full_name, role, email, phone,"
            " pseudonym) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, pw, name, role, email, phone, new_pseudonym()),
        )

    user_ids = {
        row["username"]: row["id"]
        for row in conn.execute("SELECT id, username FROM users")
    }

    for acct_no, owner, nickname, atype, opening in _SEED_ACCOUNTS:
        opening_cents = int(round(opening * 100))
        # Opening balance, dated ~35 days ago so it precedes all activity.
        running = opening_cents
        conn.execute(
            "INSERT INTO accounts (account_number, owner_id, nickname,"
            " account_type, balance_cents) VALUES (?, ?, ?, ?, ?)",
            (acct_no, user_ids[owner], nickname, atype, opening_cents),
        )
        conn.execute(
            "INSERT INTO transactions (account_number, ts, amount_cents,"
            " balance_cents, description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
            (acct_no, _ts_days_ago(35), opening_cents, running, "Opening balance", None),
        )

        for days_ago, amount, desc, counterparty in _SEED_ACTIVITY.get(acct_no, []):
            cents = int(round(amount * 100))
            running += cents
            conn.execute(
                "INSERT INTO transactions (account_number, ts, amount_cents,"
                " balance_cents, description, counterparty) VALUES (?, ?, ?, ?, ?, ?)",
                (acct_no, _ts_days_ago(days_ago), cents, running, desc, counterparty),
            )

        # The account's current balance is the running total after all activity.
        conn.execute(
            "UPDATE accounts SET balance_cents = ? WHERE account_number = ?",
            (running, acct_no),
        )


def init_db(force: bool = False) -> None:
    """Create schema and seed if empty (or if ``force``).

    A plain restart calls ``init_db()`` (force=False), which seeds ONLY when the
    database is empty — so existing data is preserved across restarts. Use
    ``reset_db()`` to deliberately rebuild from the seed dataset.
    """
    with connect() as conn:
        if force:
            conn.executescript(
                "DROP TABLE IF EXISTS loan_payments;"
                "DROP TABLE IF EXISTS loans;"
                "DROP TABLE IF EXISTS loan_limits;"
                "DROP TABLE IF EXISTS transactions;"
                "DROP TABLE IF EXISTS accounts;"
                "DROP TABLE IF EXISTS users;"
            )
        conn.executescript(SCHEMA)
        _migrate(conn)

        already = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if already:
            return
        _seed(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive column migrations for databases created before a schema change.

    ``CREATE TABLE IF NOT EXISTS`` never adds columns to an existing table, so
    new nullable/defaulted columns are backfilled here for older DBs.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(loans)")}
    if "service_charge_cents" not in cols:
        conn.execute(
            "ALTER TABLE loans ADD COLUMN service_charge_cents INTEGER NOT NULL DEFAULT 0"
        )

    # Security-log correlation handle. Add the column, then backfill a unique
    # random pseudonym per existing user (one-off, idempotent — only rows still
    # NULL are filled).
    user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    if "pseudonym" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN pseudonym TEXT UNIQUE")
    for row in conn.execute("SELECT id FROM users WHERE pseudonym IS NULL").fetchall():
        conn.execute(
            "UPDATE users SET pseudonym = ? WHERE id = ?",
            (new_pseudonym(), row["id"]),
        )


def reset_db() -> None:
    """Drop everything and rebuild from the canonical seed dataset."""
    init_db(force=True)

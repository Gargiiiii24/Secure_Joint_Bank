import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5000";

type Account = {
  account_id: number;
  account_number: string;
  account_type: string;
  total_members: number;
  required_approvals: number;
  balance: number;
  status: string;
  role?: string;
};

type Transaction = {
  transaction_id: number;
  account_id: number;
  initiated_by: number;
  beneficiary: string;
  amount: number;
  transaction_hash: string;
  required_approvals: number;
  status: string;
  created_at: string;
  expires_at?: string;
};

type Approval = {
  approval_id: number;
  transaction_id: number;
  user_id: number;
  authentication_status: boolean;
  biometric_verified: boolean;
  decision: string;
  cryptographic_proof?: string;
  signature?: string;
  approval_time?: string;
  user_name?: string;
};

type SecurityEvent = {
  event_id: number;
  transaction_id: number;
  event_type: string;
  actor?: string;
  original_value?: string;
  modified_value?: string;
  detected: boolean;
  event_time: string;
};

type Verification = {
  transaction_id: number;
  database_status: string;
  stored_hash: string;
  calculated_hash: string;
  hash_valid: boolean;
  valid_signatures: number;
  required_approvals: number;
  threshold_valid: boolean;
  cryptographically_authorized: boolean;
  approvals: Approval[];
};

function App() {
  const [token, setToken] = useState(
    localStorage.getItem("sjb_token") || ""
  );

  const [user, setUser] = useState<any>(() => {
    const saved = localStorage.getItem("sjb_user");
    return saved ? JSON.parse(saved) : null;
  });

  const [page, setPage] = useState("dashboard");
  const [theme, setTheme] = useState(
    localStorage.getItem("sjb_theme") || "banking"
  );
  const [notifications, setNotifications] = useState(
    localStorage.getItem("sjb_notifications") !== "off"
  );

  const [accounts, setAccounts] = useState<Account[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [members, setMembers] = useState<any[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);

  const [selectedTransaction, setSelectedTransaction] =
    useState<Transaction | null>(null);

  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [verification, setVerification] =
    useState<Verification | null>(null);

  const [showDetails, setShowDetails] = useState(false);

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  // Login fields
  const [mobile, setMobile] = useState("");
  const [password, setPassword] = useState("");

  // Transaction fields
  const [beneficiary, setBeneficiary] = useState("");
  const [amount, setAmount] = useState("");
  const [selectedAccount, setSelectedAccount] = useState("");

  // --------------------------------------------------
  // API HELPER
  // --------------------------------------------------

  async function api(
    endpoint: string,
    options: RequestInit = {}
  ) {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(`${API}${endpoint}`, {
      ...options,
      headers: {
        ...headers,
        ...(options.headers || {}),
      },
    });

    let data: any = {};

    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok) {
      throw new Error(
        data.error ||
          data.message ||
          `Request failed (${response.status})`
      );
    }

    return data;
  }

  // --------------------------------------------------
  // LOGIN
  // --------------------------------------------------

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();

    setError("");
    setMessage("");
    setLoading(true);

    try {
      const data = await fetch(`${API}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          mobile,
          password,
        }),
      });

      const result = await data.json();

      if (!data.ok) {
        throw new Error(result.error || "Login failed");
      }

      localStorage.setItem("sjb_token", result.token);
      localStorage.setItem(
        "sjb_user",
        JSON.stringify(result.user)
      );

      setToken(result.token);
      setUser(result.user);
      setPage("dashboard");

      setMobile("");
      setPassword("");
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  // --------------------------------------------------
  // LOGOUT
  // --------------------------------------------------

  function logout() {
    localStorage.removeItem("sjb_token");
    localStorage.removeItem("sjb_user");

    setToken("");
    setUser(null);
    setAccounts([]);
    setTransactions([]);
    setMembers([]);
    setSecurityEvents([]);
    setVerification(null);
    setApprovals([]);
  }

  // --------------------------------------------------
  // LOAD DATA
  // --------------------------------------------------

  async function loadAccounts() {
    try {
      const data = await api("/accounts");
      setAccounts(data.accounts || data || []);
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function loadTransactions() {
    try {
      const data = await api("/transactions");
      setTransactions(data.transactions || data || []);
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function loadMembers(accountId: number) {
    try {
      const data = await api(`/accounts/${accountId}/members`);
      setMembers(data.members || data || []);
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function loadApprovals(transactionId: number) {
    try {
      const data = await api(
        `/transactions/${transactionId}/approvals`
      );

      setApprovals(data.approvals || data || []);
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function loadSecurityEvents(transactionId: number) {
    try {
      const data = await api(
        `/security-events/${transactionId}`
      );

      setSecurityEvents(data.events || data || []);
    } catch (err: any) {
      setError(err.message);
    }
  }

  // --------------------------------------------------
  // THEME / SETTINGS
  // --------------------------------------------------

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sjb_theme", theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem(
      "sjb_notifications",
      notifications ? "on" : "off"
    );
  }, [notifications]);

  function changeTheme(nextTheme: string) {
    setTheme(nextTheme);
  }

  // --------------------------------------------------
  // INITIAL LOAD
  // --------------------------------------------------

  useEffect(() => {
    if (!token) return;

    loadAccounts();
    loadTransactions();
  }, [token]);

  // --------------------------------------------------
  // CREATE TRANSACTION
  // --------------------------------------------------

  async function createTransaction(e: React.FormEvent) {
    e.preventDefault();

    setError("");
    setMessage("");

    if (!selectedAccount) {
      setError("Please select an account.");
      return;
    }

    if (!beneficiary.trim()) {
      setError("Please enter beneficiary.");
      return;
    }

    if (!amount || Number(amount) <= 0) {
      setError("Please enter a valid amount.");
      return;
    }

    setLoading(true);

    try {
      const data = await api("/transactions", {
        method: "POST",
        body: JSON.stringify({
          account_id: Number(selectedAccount),
          beneficiary: beneficiary.trim(),
          amount: Number(amount),
        }),
      });

      setMessage(
        data.message ||
          `Transaction #${data.transaction_id} created successfully.`
      );

      setBeneficiary("");
      setAmount("");
      setSelectedAccount("");

      await loadTransactions();

      setPage("transactions");
    } catch (err: any) {
      setError(err.message || "Unable to create transaction.");
    } finally {
      setLoading(false);
    }
  }

  // --------------------------------------------------
  // OPEN DETAILS
  // --------------------------------------------------

  async function openDetails(transaction: Transaction) {
    setSelectedTransaction(transaction);
    setShowDetails(true);

    setError("");
    setMessage("");

    await loadApprovals(transaction.transaction_id);
  }

  // --------------------------------------------------
  // VERIFY TRANSACTION
  // --------------------------------------------------

  async function verifyTransaction(transactionId: number) {
    setError("");
    setMessage("");
    setLoading(true);

    try {
      const data = await api(`/verify/${transactionId}`);

      setVerification(data);
      setSelectedTransaction(
        transactions.find(
          (t) => t.transaction_id === transactionId
        ) || null
      );

      setPage("verification");
    } catch (err: any) {
      setError(err.message || "Verification failed.");
    } finally {
      setLoading(false);
    }
  }

  // --------------------------------------------------
  // APPROVE TRANSACTION
  // --------------------------------------------------

  async function approveTransaction(transactionId: number) {
    setError("");
    setMessage("");
    setLoading(true);

    try {
      const data = await api(
        `/transactions/${transactionId}/approve`,
        {
          method: "POST",
        }
      );

      setMessage(
        data.message || "Transaction approval submitted."
      );

      await loadTransactions();
      await loadApprovals(transactionId);
    } catch (err: any) {
      setError(err.message || "Approval failed.");
    } finally {
      setLoading(false);
    }
  }

  // --------------------------------------------------
  // EXECUTE TRANSACTION
  // --------------------------------------------------

  async function executeTransaction(transactionId: number) {
    if (
      !window.confirm(
        "Are you sure you want to execute this transaction?"
      )
    ) {
      return;
    }

    setError("");
    setMessage("");
    setLoading(true);

    try {
      const data = await api(
        `/transactions/${transactionId}/execute`,
        {
          method: "POST",
        }
      );

      setMessage(
        data.message || "Transaction executed successfully."
      );

      await loadTransactions();
      await loadAccounts();
    } catch (err: any) {
      setError(err.message || "Transaction execution failed.");
    } finally {
      setLoading(false);
    }
  }

  // --------------------------------------------------
  // SECURITY LOG
  // --------------------------------------------------

  async function openSecurityLog(transactionId: number) {
    setSelectedTransaction(
      transactions.find(
        (t) => t.transaction_id === transactionId
      ) || null
    );

    await loadSecurityEvents(transactionId);

    setPage("security");
  }

  // --------------------------------------------------
  // LOGIN SCREEN
  // --------------------------------------------------

  if (!token || !user) {
    return (
      <div className="login-page">
        <div className="login-left">
          <div className="brand">
            <div className="brand-icon">S</div>
            <span>Secure Joint Bank</span>
          </div>

          <div className="login-content">
            <div className="shield-large">🛡️</div>

            <h1>Secure Joint Banking</h1>

            <p>
              Cryptographically protected transaction
              authorization for multi-holder bank accounts.
            </p>

            <div className="security-points">
              <div>✓ RSA Digital Signatures</div>
              <div>✓ SHA-256 Transaction Integrity</div>
              <div>✓ Threshold Approval</div>
              <div>✓ Tamper-Evident Security Logs</div>
            </div>
          </div>
        </div>

        <div className="login-right">
          <div className="login-card">
            <h2>Welcome Back</h2>

            <p className="login-subtitle">
              Sign in to access your secure banking dashboard.
            </p>

            {error && (
              <div className="alert error">
                {error}
              </div>
            )}

            <form onSubmit={handleLogin}>
              <label>Mobile Number</label>

              <input
                type="text"
                value={mobile}
                onChange={(e) => setMobile(e.target.value)}
                placeholder="Enter mobile number"
                autoComplete="username"
              />

              <label>Password</label>

              <input
                type="password"
                value={password}
                onChange={(e) =>
                  setPassword(e.target.value)
                }
                placeholder="Enter password"
                autoComplete="current-password"
              />

              <button
                className="primary-button login-button"
                type="submit"
                disabled={loading}
              >
                {loading ? "Signing in..." : "Secure Login"}
              </button>
            </form>

            <div className="login-footer">
              Protected by cryptographic authorization
            </div>
          </div>
        </div>
      </div>
    );
  }

  // --------------------------------------------------
  // DASHBOARD CALCULATIONS
  // --------------------------------------------------

  const totalBalance = accounts.reduce(
    (sum, account) => sum + Number(account.balance || 0),
    0
  );

  const pendingCount = transactions.filter(
    (t) => t.status === "PENDING"
  ).length;

  const executedCount = transactions.filter(
    (t) => t.status === "EXECUTED"
  ).length;

  const approvedCount = transactions.filter(
    (t) => t.status === "APPROVED"
  ).length;

  // --------------------------------------------------
  // RENDER
  // --------------------------------------------------

  return (
    <div className="app">
      {/* SIDEBAR */}

      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">S</div>

          <div>
            <strong>Secure Joint Bank</strong>
            <span>Secure Banking</span>
          </div>
        </div>

        <div className="user-mini">
          <div className="avatar">
            {user.name?.charAt(0)?.toUpperCase() || "U"}
          </div>

          <div>
            <strong>{user.name}</strong>
            <span>Joint Account Holder</span>
          </div>
        </div>

        <nav>
          <button
            className={
              page === "dashboard" ? "nav-item active" : "nav-item"
            }
            onClick={() => setPage("dashboard")}
          >
            <span>▦</span>
            Dashboard
          </button>

          <button
            className={
              page === "members" ? "nav-item active" : "nav-item"
            }
            onClick={() => {
              setPage("members");

              if (accounts.length > 0) {
                loadMembers(accounts[0].account_id);
              }
            }}
          >
            <span>👥</span>
            Members
          </button>

          <button
            className={
              page === "new" ? "nav-item active" : "nav-item"
            }
            onClick={() => setPage("new")}
          >
            <span>＋</span>
            New Transaction
          </button>

          <button
            className={
              page === "transactions"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => {
              setPage("transactions");
              loadTransactions();
            }}
          >
            <span>⇄</span>
            Transactions
          </button>

          <button
            className={
              page === "verification"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setPage("verification")}
          >
            <span>✓</span>
            Verification
          </button>

          <button
            className={
              page === "security"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setPage("security")}
          >
            <span>🔐</span>
            Security Log
          </button>

          <button
            className={
              page === "settings"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setPage("settings")}
          >
            <span>⚙</span>
            Settings
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="secure-status">
            <span className="green-dot"></span>

            <div>
              <strong>System Secure</strong>
              <span>Cryptographic protection active</span>
            </div>
          </div>

          <button className="logout-button" onClick={logout}>
            ↪ Logout
          </button>
        </div>
      </aside>

      {/* MAIN */}

      <main className="main">
        <header className="topbar">
          <div>
            <h1>
              {page === "dashboard" && "Dashboard"}
              {page === "members" && "Account Members"}
              {page === "new" && "New Transaction"}
              {page === "transactions" && "Transactions"}
              {page === "verification" && "Cryptographic Verification"}
              {page === "security" && "Security Log"}
              {page === "settings" && "Settings"}
            </h1>

            <p>
              Secure Joint Bank Authorization System
            </p>
          </div>

          <div className="top-user">
            <div className="top-avatar">
              {user.name?.charAt(0)?.toUpperCase() || "U"}
            </div>

            <div>
              <strong>{user.name}</strong>
              <span>Authenticated</span>
            </div>
          </div>
        </header>

        {error && (
          <div className="global-alert error">
            <span>⚠</span>
            {error}
            <button onClick={() => setError("")}>×</button>
          </div>
        )}

        {message && (
          <div className="global-alert success">
            <span>✓</span>
            {message}
            <button onClick={() => setMessage("")}>×</button>
          </div>
        )}

        {/* ================= DASHBOARD ================= */}

        {page === "dashboard" && (
          <div className="page-content">
            <div className="welcome-card">
              <div>
                <span className="eyebrow">
                  SECURE BANKING
                </span>

                <h2>
                  Welcome, {user.name?.split(" ")[0]}
                </h2>

                <p>
                  Your joint account transactions are
                  protected by multi-party cryptographic
                  authorization.
                </p>
              </div>

              <div className="welcome-shield">🛡️</div>
            </div>

            <div className="stats-grid">
              <div className="stat-card">
                <span>Total Balance</span>
                <strong>
                  ₹
                  {totalBalance.toLocaleString("en-IN", {
                    minimumFractionDigits: 2,
                  })}
                </strong>
                <small>Across joint accounts</small>
              </div>

              <div className="stat-card">
                <span>Total Transactions</span>
                <strong>{transactions.length}</strong>
                <small>Recorded securely</small>
              </div>

              <div className="stat-card">
                <span>Pending</span>
                <strong>{pendingCount}</strong>
                <small>Awaiting authorization</small>
              </div>

              <div className="stat-card">
                <span>Executed</span>
                <strong>{executedCount}</strong>
                <small>Successfully completed</small>
              </div>
            </div>

            <div className="section-header">
              <div>
                <h2>Recent Transactions</h2>
                <p>Your latest secure transactions</p>
              </div>

              <button
                className="outline-button"
                onClick={() => setPage("transactions")}
              >
                View All
              </button>
            </div>

            <TransactionTable
              transactions={transactions.slice(0, 5)}
              onDetails={openDetails}
              onVerify={verifyTransaction}
              onApprove={approveTransaction}
              onExecute={executeTransaction}
              onLog={openSecurityLog}
              loading={loading}
              userId={user.user_id}
            />
          </div>
        )}

        {/* ================= MEMBERS ================= */}

        {page === "members" && (
          <div className="page-content">
            <div className="section-header">
              <div>
                <h2>Joint Account Members</h2>
                <p>
                  Authorized holders of your joint account
                </p>
              </div>
            </div>

            <div className="account-selector">
              <label>Select Account</label>

              <select
                value={selectedAccount}
                onChange={(e) => {
                  setSelectedAccount(e.target.value);

                  if (e.target.value) {
                    loadMembers(Number(e.target.value));
                  }
                }}
              >
                <option value="">
                  Select account
                </option>

                {accounts.map((account) => (
                  <option
                    key={account.account_id}
                    value={account.account_id}
                  >
                    {account.account_number}
                  </option>
                ))}
              </select>
            </div>

            <div className="members-grid">
              {members.map((member: any) => (
                <div
                  className="member-card"
                  key={member.user_id}
                >
                  <div className="member-avatar">
                    {member.name
                      ?.charAt(0)
                      ?.toUpperCase() || "U"}
                  </div>

                  <div>
                    <h3>{member.name}</h3>

                    <p>
                      {member.email ||
                        member.mobile ||
                        "Account holder"}
                    </p>

                    <span className="role-badge">
                      {member.role || "MEMBER"}
                    </span>
                  </div>
                </div>
              ))}

              {members.length === 0 && (
                <div className="empty-state">
                  Select an account to view members.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ================= NEW TRANSACTION ================= */}

        {page === "new" && (
          <div className="page-content narrow">
            <div className="form-card">
              <div className="form-header">
                <div className="form-icon">⇄</div>

                <div>
                  <h2>Create Secure Transaction</h2>

                  <p>
                    This transaction will require
                    cryptographic approval from authorized
                    joint account holders.
                  </p>
                </div>
              </div>

              <form onSubmit={createTransaction}>
                <div className="form-group">
                  <label>Joint Account</label>

                  <select
                    value={selectedAccount}
                    onChange={(e) =>
                      setSelectedAccount(e.target.value)
                    }
                  >
                    <option value="">
                      Select joint account
                    </option>

                    {accounts.map((account) => (
                      <option
                        key={account.account_id}
                        value={account.account_id}
                      >
                        {account.account_number} — ₹
                        {Number(
                          account.balance
                        ).toLocaleString("en-IN")}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label>Beneficiary</label>

                  <input
                    type="text"
                    value={beneficiary}
                    onChange={(e) =>
                      setBeneficiary(e.target.value)
                    }
                    placeholder="Enter beneficiary name"
                    autoComplete="off"
                  />
                </div>

                <div className="form-group">
                  <label>Amount</label>

                  <div className="amount-input">
                    <span>₹</span>

                    <input
                      type="number"
                      value={amount}
                      onChange={(e) =>
                        setAmount(e.target.value)
                      }
                      placeholder="0.00"
                      min="0.01"
                      step="0.01"
                    />
                  </div>
                </div>

                <div className="security-info">
                  <div>🔐</div>

                  <div>
                    <strong>Cryptographic Protection</strong>

                    <p>
                      SHA-256 will bind this transaction to
                      its exact details. Each approval will
                      require a valid RSA digital signature.
                    </p>
                  </div>
                </div>

                <button
                  className="primary-button full"
                  type="submit"
                  disabled={loading}
                >
                  {loading
                    ? "Creating..."
                    : "Create Secure Transaction"}
                </button>
              </form>
            </div>
          </div>
        )}

        {/* ================= TRANSACTIONS ================= */}

        {page === "transactions" && (
          <div className="page-content">
            <div className="section-header">
              <div>
                <h2>All Transactions</h2>
                <p>
                  Cryptographically protected transaction
                  records
                </p>
              </div>

              <button
                className="primary-button"
                onClick={() => setPage("new")}
              >
                + New Transaction
              </button>
            </div>

            <TransactionTable
              transactions={transactions}
              onDetails={openDetails}
              onVerify={verifyTransaction}
              onApprove={approveTransaction}
              onExecute={executeTransaction}
              onLog={openSecurityLog}
              loading={loading}
              userId={user.user_id}
            />
          </div>
        )}

        {/* ================= VERIFICATION ================= */}

        {page === "verification" && (
          <div className="page-content">
            {!verification ? (
              <>
                <div className="section-header">
                  <div>
                    <h2>Select Transaction</h2>

                    <p>
                      Verify transaction integrity and
                      cryptographic authorization.
                    </p>
                  </div>
                </div>

                <TransactionTable
                  transactions={transactions}
                  onDetails={openDetails}
                  onVerify={verifyTransaction}
                  onApprove={approveTransaction}
                  onExecute={executeTransaction}
                  onLog={openSecurityLog}
                  loading={loading}
                  userId={user.user_id}
                />
              </>
            ) : (
              <>
                <div className="verification-header">
                  <div>
                    <h2>
                      Transaction #
                      {verification.transaction_id}
                    </h2>

                    <p>
                      Cryptographic security verification
                    </p>
                  </div>

                  <button
                    className="outline-button"
                    onClick={() =>
                      setVerification(null)
                    }
                  >
                    ← Back
                  </button>
                </div>

                <div className="verification-grid">
                  <SecurityCheck
                    title="Transaction Hash"
                    valid={verification.hash_valid}
                    description={
                      verification.hash_valid
                        ? "Transaction data has not been modified."
                        : "Transaction data has been modified."
                    }
                  />

                  <SecurityCheck
                    title="RSA Signatures"
                    valid={
                      verification.valid_signatures > 0
                    }
                    description={`${verification.valid_signatures} valid digital signature(s) found.`}
                  />

                  <SecurityCheck
                    title="Threshold Requirement"
                    valid={verification.threshold_valid}
                    description={`${verification.valid_signatures} / ${verification.required_approvals} approvals required.`}
                  />

                  <SecurityCheck
                    title="Cryptographic Authorization"
                    valid={
                      verification.cryptographically_authorized
                    }
                    description={
                      verification.cryptographically_authorized
                        ? "Transaction is cryptographically authorized."
                        : "Transaction is NOT cryptographically authorized."
                    }
                  />
                </div>

                <div className="hash-card">
                  <h3>Transaction Hash Comparison</h3>

                  <div className="hash-row">
                    <span>Stored Hash</span>

                    <code>
                      {verification.stored_hash}
                    </code>
                  </div>

                  <div className="hash-row">
                    <span>Calculated Hash</span>

                    <code>
                      {verification.calculated_hash}
                    </code>
                  </div>
                </div>

                <div className="approval-card">
                  <h3>Cryptographic Approvals</h3>

                  {verification.approvals?.map(
                    (approval) => (
                      <div
                        className="approval-row"
                        key={approval.approval_id}
                      >
                        <div className="approval-avatar">
                          {approval.user_name
                            ?.charAt(0)
                            ?.toUpperCase() ||
                            String(
                              approval.user_id
                            ).charAt(0)}
                        </div>

                        <div className="approval-info">
                          <strong>
                            {approval.user_name ||
                              `User ${approval.user_id}`}
                          </strong>

                          <span>
                            {approval.decision}
                          </span>
                        </div>

                        <div
                          className={
                            approval.signature
                              ? "signature-valid"
                              : "signature-invalid"
                          }
                        >
                          {approval.signature
                            ? "✓ Valid Signature"
                            : "✕ Invalid"}
                        </div>
                      </div>
                    )
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* ================= SECURITY LOG ================= */}

        {page === "security" && (
          <div className="page-content">
            <div className="section-header">
              <div>
                <h2>Security Events</h2>

                <p>
                  Tampering detection and transaction
                  security audit trail
                </p>
              </div>
            </div>

            {selectedTransaction && (
              <div className="selected-transaction">
                Transaction #
                {selectedTransaction.transaction_id}
                {" — "}
                {selectedTransaction.beneficiary}
              </div>
            )}

            <div className="security-log">
              {securityEvents.length === 0 ? (
                <div className="empty-state">
                  No security events found for the selected
                  transaction.
                </div>
              ) : (
                securityEvents.map((event) => (
                  <div
                    className="security-event"
                    key={event.event_id}
                  >
                    <div className="event-icon">
                      {event.detected ? "⚠" : "✓"}
                    </div>

                    <div className="event-content">
                      <div className="event-top">
                        <strong>
                          {event.event_type}
                        </strong>

                        <span>
                          {new Date(
                            event.event_time
                          ).toLocaleString()}
                        </span>
                      </div>

                      <p>
                        Actor:{" "}
                        {event.actor || "SYSTEM"}
                      </p>

                      {event.original_value && (
                        <div className="event-value">
                          <span>Original:</span>
                          <code>
                            {event.original_value}
                          </code>
                        </div>
                      )}

                      {event.modified_value && (
                        <div className="event-value">
                          <span>Modified:</span>
                          <code>
                            {event.modified_value}
                          </code>
                        </div>
                      )}
                    </div>

                    {event.detected && (
                      <span className="danger-badge">
                        DETECTED
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </main>


        {/* ================= SETTINGS ================= */}

        {page === "settings" && (
          <div className="page-content settings-page">
            <div className="settings-hero">
              <div>
                <span className="eyebrow">PREFERENCES</span>
                <h2>Settings & Personalization</h2>
                <p>
                  Customize the Secure Joint Bank dashboard,
                  appearance and account preferences.
                </p>
              </div>
              <div className="settings-hero-icon">⚙</div>
            </div>

            <div className="settings-layout">
              <section className="settings-card">
                <div className="settings-card-header">
                  <div className="settings-card-icon">🎨</div>
                  <div>
                    <h3>Appearance</h3>
                    <p>Choose your preferred banking interface theme.</p>
                  </div>
                </div>

                <div className="theme-grid">
                  {[
                    ["banking", "Banking Blue", "Professional blue"],
                    ["midnight", "Midnight", "Deep dark mode"],
                    ["emerald", "Emerald", "Modern green"],
                    ["purple", "Royal Purple", "Elegant purple"],
                    ["ocean", "Ocean", "Cool cyan"],
                    ["rose", "Rose", "Soft modern rose"],
                    ["contrast", "High Contrast", "Maximum readability"],
                    ["light", "Clean Light", "Bright interface"],
                  ].map(([id, name, description]) => (
                    <button
                      key={id}
                      className={`theme-option ${theme === id ? "selected" : ""} theme-${id}`}
                      onClick={() => changeTheme(id)}
                      type="button"
                    >
                      <span className="theme-preview">
                        <span></span><span></span><span></span>
                      </span>
                      <span className="theme-option-text">
                        <strong>{name}</strong>
                        <small>{description}</small>
                      </span>
                      <span className="theme-check">
                        {theme === id ? "✓" : ""}
                      </span>
                    </button>
                  ))}
                </div>
              </section>

              <section className="settings-card">
                <div className="settings-card-header">
                  <div className="settings-card-icon">🔔</div>
                  <div>
                    <h3>Notifications</h3>
                    <p>Control dashboard notification preferences.</p>
                  </div>
                </div>

                <div className="setting-row">
                  <div>
                    <strong>Security notifications</strong>
                    <span>Show transaction and security alerts.</span>
                  </div>
                  <button
                    type="button"
                    className={`toggle ${notifications ? "on" : ""}`}
                    onClick={() => setNotifications(!notifications)}
                    aria-label="Toggle notifications"
                  >
                    <span></span>
                  </button>
                </div>
              </section>

              <section className="settings-card">
                <div className="settings-card-header">
                  <div className="settings-card-icon">👤</div>
                  <div>
                    <h3>Account</h3>
                    <p>Your authenticated account information.</p>
                  </div>
                </div>

                <div className="account-settings-grid">
                  <div>
                    <span>Name</span>
                    <strong>{user.name || "—"}</strong>
                  </div>
                  <div>
                    <span>Mobile</span>
                    <strong>{user.mobile || "—"}</strong>
                  </div>
                  <div>
                    <span>Email</span>
                    <strong>{user.email || "Not provided"}</strong>
                  </div>
                  <div>
                    <span>Authentication</span>
                    <strong className="secure-text">✓ Authenticated</strong>
                  </div>
                </div>
              </section>

              <section className="settings-card security-settings-card">
                <div className="settings-card-header">
                  <div className="settings-card-icon">🔐</div>
                  <div>
                    <h3>Security</h3>
                    <p>Cryptographic protection currently enabled.</p>
                  </div>
                </div>

                <div className="security-setting-list">
                  <div><span>SHA-256 transaction integrity</span><strong>ACTIVE</strong></div>
                  <div><span>RSA digital signatures</span><strong>ACTIVE</strong></div>
                  <div><span>Threshold authorization</span><strong>ACTIVE</strong></div>
                  <div><span>Tamper-evident audit logging</span><strong>ACTIVE</strong></div>
                </div>
              </section>

              <section className="settings-card danger-settings-card">
                <div className="settings-card-header">
                  <div className="settings-card-icon">🚪</div>
                  <div>
                    <h3>Session</h3>
                    <p>Sign out of this Secure Joint Bank session.</p>
                  </div>
                </div>

                <button
                  type="button"
                  className="settings-logout"
                  onClick={logout}
                >
                  <span>↪</span>
                  Logout from this account
                </button>
              </section>
            </div>
          </div>
        )}

      {/* ================= DETAILS MODAL ================= */}

      {showDetails && selectedTransaction && (
        <div
          className="modal-overlay"
          onClick={() => setShowDetails(false)}
        >
          <div
            className="details-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <div>
                <span>TRANSACTION</span>

                <h2>
                  #{selectedTransaction.transaction_id}
                </h2>
              </div>

              <button
                className="close-button"
                onClick={() => setShowDetails(false)}
              >
                ×
              </button>
            </div>

            <div className="transaction-summary">
              <div>
                <span>Beneficiary</span>

                <strong>
                  {selectedTransaction.beneficiary}
                </strong>
              </div>

              <div>
                <span>Amount</span>

                <strong>
                  ₹
                  {Number(
                    selectedTransaction.amount
                  ).toLocaleString("en-IN", {
                    minimumFractionDigits: 2,
                  })}
                </strong>
              </div>

              <div>
                <span>Status</span>

                <StatusBadge
                  status={selectedTransaction.status}
                />
              </div>
            </div>

            <div className="details-section">
              <h3>Approval Records</h3>

              {approvals.length === 0 ? (
                <div className="empty-state">
                  No approvals recorded yet.
                </div>
              ) : (
                approvals.map((approval) => (
                  <div
                    className="approval-row"
                    key={approval.approval_id}
                  >
                    <div className="approval-avatar">
                      {String(
                        approval.user_id
                      ).charAt(0)}
                    </div>

                    <div className="approval-info">
                      <strong>
                        {approval.user_name ||
                          `User ${approval.user_id}`}
                      </strong>

                      <span>
                        {approval.decision}
                      </span>
                    </div>

                    <div>
                      {approval.signature ? (
                        <span className="signature-valid">
                          ✓ Cryptographically Signed
                        </span>
                      ) : (
                        <span className="signature-invalid">
                          Pending
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="modal-actions">
              <button
                className="outline-button"
                onClick={() => {
                  setShowDetails(false);
                  verifyTransaction(
                    selectedTransaction.transaction_id
                  );
                }}
              >
                Verify
              </button>

              {selectedTransaction.status ===
                "PENDING" && (
                <button
                  className="primary-button"
                  onClick={() =>
                    approveTransaction(
                      selectedTransaction.transaction_id
                    )
                  }
                  disabled={loading}
                >
                  Approve
                </button>
              )}

              {selectedTransaction.status ===
                "APPROVED" && (
                <button
                  className="primary-button"
                  onClick={() =>
                    executeTransaction(
                      selectedTransaction.transaction_id
                    )
                  }
                  disabled={loading}
                >
                  Execute
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ==================================================
// TRANSACTION TABLE
// ==================================================

function TransactionTable({
  transactions,
  onDetails,
  onVerify,
  onApprove,
  onExecute,
  onLog,
  loading,
  userId,
}: {
  transactions: Transaction[];
  onDetails: (transaction: Transaction) => void;
  onVerify: (id: number) => void;
  onApprove: (id: number) => void;
  onExecute: (id: number) => void;
  onLog: (id: number) => void;
  loading: boolean;
  userId: number;
}) {
  if (transactions.length === 0) {
    return (
      <div className="empty-state large">
        <div className="empty-icon">⇄</div>
        <h3>No Transactions</h3>
        <p>
          There are currently no transactions to display.
        </p>
      </div>
    );
  }

  return (
    <div className="table-card">
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Beneficiary</th>
              <th>Amount</th>
              <th>Required</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>

          <tbody>
            {transactions.map((transaction) => (
              <tr key={transaction.transaction_id}>
                <td>
                  <strong>
                    #{transaction.transaction_id}
                  </strong>
                </td>

                <td>
                  <div className="beneficiary">
                    <div className="beneficiary-avatar">
                      {transaction.beneficiary
                        ?.charAt(0)
                        ?.toUpperCase()}
                    </div>

                    <span>
                      {transaction.beneficiary}
                    </span>
                  </div>
                </td>

                <td className="amount-cell">
                  ₹
                  {Number(
                    transaction.amount
                  ).toLocaleString("en-IN", {
                    minimumFractionDigits: 2,
                  })}
                </td>

                <td>
                  <span className="threshold">
                    {transaction.required_approvals} approvals
                  </span>
                </td>

                <td>
                  <StatusBadge
                    status={transaction.status}
                  />
                </td>

                <td>
                  {transaction.created_at
                    ? new Date(
                        transaction.created_at
                      ).toLocaleString()
                    : "-"}
                </td>

                <td>
                  <div className="actions">
                    <button
                      className="small-button"
                      onClick={() =>
                        onDetails(transaction)
                      }
                    >
                      Details
                    </button>

                    <button
                      className="small-button verify"
                      onClick={() =>
                        onVerify(
                          transaction.transaction_id
                        )
                      }
                    >
                      Verify
                    </button>

                    {transaction.status ===
                      "PENDING" &&
                      transaction.initiated_by !==
                        userId && (
                        <button
                          className="small-button approve"
                          onClick={() =>
                            onApprove(
                              transaction.transaction_id
                            )
                          }
                          disabled={loading}
                        >
                          Approve
                        </button>
                      )}

                    {transaction.status ===
                      "APPROVED" && (
                      <button
                        className="small-button execute"
                        onClick={() =>
                          onExecute(
                            transaction.transaction_id
                          )
                        }
                        disabled={loading}
                      >
                        Execute
                      </button>
                    )}

                    <button
                      className="small-button log"
                      onClick={() =>
                        onLog(
                          transaction.transaction_id
                        )
                      }
                    >
                      Log
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ==================================================
// STATUS BADGE
// ==================================================

function StatusBadge({ status }: { status: string }) {
  const normalized = status?.toUpperCase();

  return (
    <span
      className={`status-badge ${normalized?.toLowerCase()}`}
    >
      <span className="status-dot"></span>
      {normalized}
    </span>
  );
}

// ==================================================
// SECURITY CHECK
// ==================================================

function SecurityCheck({
  title,
  valid,
  description,
}: {
  title: string;
  valid: boolean;
  description: string;
}) {
  return (
    <div
      className={`security-check ${
        valid ? "valid" : "invalid"
      }`}
    >
      <div className="check-icon">
        {valid ? "✓" : "✕"}
      </div>

      <div>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>

      <strong>
        {valid ? "VALID" : "INVALID"}
      </strong>
    </div>
  );
}

export default App;
import { useState, useEffect, useCallback, useRef } from 'react';
import { api, setToken, clearToken, hasToken } from './api';
import './index.css';

// ── Utility ──────────────────────────────────────────────────────────────────
const STATUS_COLOR = {
  ACTIVE:        '#22c55e',
  SUSPENDED:     '#f59e0b',
  PENDING:       '#60a5fa',
  DEPROVISIONED: '#6b7280',
};

const ROLE_BADGE = {
  admin:      '#ef4444',
  manager:    '#8b5cf6',
  developer:  '#3b82f6',
  contractor: '#f97316',
};

function Badge({ label, color }) {
  return (
    <span style={{
      background: `${color}22`,
      color,
      border: `1px solid ${color}44`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.05em',
      textTransform: 'uppercase',
    }}>
      {label}
    </span>
  );
}

function Spinner() {
  return <div className="spinner" />;
}

// ── Login Screen ──────────────────────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [email, setEmail] = useState('admin@nexus.local');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await api.login(email, password);
      setToken(res.access_token);
      onLogin(res.access_token);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-logo">
          <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
            <rect width="40" height="40" rx="10" fill="#0f172a"/>
            <path d="M20 8L32 14V22C32 28.627 26.627 34 20 34C13.373 34 8 28.627 8 22V14L20 8Z"
              fill="none" stroke="#38bdf8" strokeWidth="2"/>
            <circle cx="20" cy="22" r="4" fill="#38bdf8"/>
            <line x1="20" y1="18" x2="20" y2="14" stroke="#38bdf8" strokeWidth="2"/>
          </svg>
        </div>
        <h1 className="login-title">Nexus IAM</h1>
        <p className="login-sub">Identity &amp; Access Management Platform</p>

        <form onSubmit={submit} className="login-form">
          <label>Email</label>
          <input
            type="email" value={email} autoComplete="username"
            onChange={e => setEmail(e.target.value)} required
          />
          <label>Password</label>
          <input
            type="password" value={password} autoComplete="current-password"
            onChange={e => setPassword(e.target.value)} required
            placeholder="••••••••••"
          />
          {error && <div className="error-msg">{error}</div>}
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? <Spinner /> : 'Authenticate'}
          </button>
        </form>

        <p className="login-hint">Default: admin@nexus.local / ChangeMe!9</p>
      </div>
    </div>
  );
}

// ── Create User Modal ─────────────────────────────────────────────────────────
function CreateUserModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ email: '', password: '', full_name: '', role: 'developer' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.createUser(form);
      onCreated();
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Provision Identity</h2>
          <button className="btn-icon" onClick={onClose}>✕</button>
        </div>

        <form onSubmit={submit} className="login-form">
          <label>Full Name</label>
          <input value={form.full_name} onChange={e => set('full_name', e.target.value)} required />

          <label>Email Address</label>
          <input type="email" value={form.email} onChange={e => set('email', e.target.value)} required />

          <label>Password</label>
          <input
            type="password" value={form.password}
            onChange={e => set('password', e.target.value)}
            placeholder="Min 10 chars, 1 uppercase, 1 digit" required
          />

          <label>Role</label>
          <select value={form.role} onChange={e => set('role', e.target.value)}>
            <option value="admin">Admin</option>
            <option value="manager">Manager</option>
            <option value="developer">Developer</option>
            <option value="contractor">Contractor</option>
          </select>

          {error && <div className="error-msg">{error}</div>}

          <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
            <button type="button" className="btn-secondary" onClick={onClose} style={{flex:1}}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading} style={{flex:1}}>
              {loading ? <Spinner /> : 'Provision'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Users Table ───────────────────────────────────────────────────────────────
function UsersTable({ onRefreshNeeded }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [actionLoading, setActionLoading] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getUsers();
      setUsers(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const suspend = async (user) => {
    setActionLoading(user.id);
    try {
      await api.updateUser(user.id, {
        status: user.status === 'SUSPENDED' ? 'ACTIVE' : 'SUSPENDED'
      });
      await load();
    } catch(err) { setError(err.message); }
    finally { setActionLoading(null); }
  };

  const deprovision = async (user) => {
    if (!confirm(`Deprovision ${user.email}? This cannot be undone.`)) return;
    setActionLoading(user.id);
    try {
      await api.deprovisionUser(user.id);
      await load();
    } catch(err) { setError(err.message); }
    finally { setActionLoading(null); }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Identity Directory</h2>
          <p className="panel-sub">{users.length} identities provisioned</p>
        </div>
        <div style={{display:'flex',gap:10}}>
          <button className="btn-secondary" onClick={load}>↻ Refresh</button>
          <button className="btn-primary" onClick={() => setShowCreate(true)}>+ Provision</button>
        </div>
      </div>

      {error && <div className="error-msg" style={{margin:'0 0 12px'}}>{error}</div>}

      {loading ? (
        <div className="center-spinner"><Spinner /></div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Identity</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className={u.status === 'DEPROVISIONED' ? 'row-dim' : ''}>
                  <td>
                    <div className="identity-cell">
                      <div className="avatar">{(u.full_name || u.email)[0].toUpperCase()}</div>
                      <div>
                        <div className="identity-name">{u.full_name || '—'}</div>
                        <div className="identity-email">{u.email}</div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <Badge label={u.role} color={ROLE_BADGE[u.role] || '#6b7280'} />
                  </td>
                  <td>
                    <Badge label={u.status} color={STATUS_COLOR[u.status] || '#6b7280'} />
                  </td>
                  <td className="muted">
                    {u.last_login
                      ? new Date(u.last_login).toLocaleDateString()
                      : 'Never'}
                  </td>
                  <td>
                    {u.status !== 'DEPROVISIONED' && (
                      <div style={{display:'flex',gap:6}}>
                        <button
                          className="btn-sm"
                          disabled={actionLoading === u.id}
                          onClick={() => suspend(u)}
                        >
                          {u.status === 'SUSPENDED' ? 'Reinstate' : 'Suspend'}
                        </button>
                        <button
                          className="btn-sm btn-danger"
                          disabled={actionLoading === u.id}
                          onClick={() => deprovision(u)}
                        >
                          Deprovision
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={load}
        />
      )}
    </div>
  );
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
function AuditPanel() {
  const [log, setLog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.getAuditLog()
      .then(setLog)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const OUTCOME_COLOR = { SUCCESS: '#22c55e', FAILURE: '#ef4444', DENIED: '#f59e0b' };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Audit Log</h2>
          <p className="panel-sub">Immutable record of all identity operations</p>
        </div>
      </div>

      {error && <div className="error-msg">{error}</div>}

      {loading ? (
        <div className="center-spinner"><Spinner /></div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Outcome</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {log.map(e => (
                <tr key={e.id}>
                  <td className="muted mono">
                    {new Date(e.created_at).toLocaleTimeString()}
                  </td>
                  <td className="identity-email">{e.actor_email || '—'}</td>
                  <td className="mono">{e.action}</td>
                  <td className="muted">{e.resource || '—'}</td>
                  <td>
                    <Badge
                      label={e.outcome}
                      color={OUTCOME_COLOR[e.outcome] || '#6b7280'}
                    />
                  </td>
                  <td className="muted mono">{e.ip_address || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────────────
function Dashboard({ onLogout, userEmail }) {
  const [tab, setTab] = useState('users');

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <svg width="28" height="28" viewBox="0 0 40 40" fill="none">
            <rect width="40" height="40" rx="10" fill="#0f172a"/>
            <path d="M20 8L32 14V22C32 28.627 26.627 34 20 34C13.373 34 8 28.627 8 22V14L20 8Z"
              fill="none" stroke="#38bdf8" strokeWidth="2"/>
            <circle cx="20" cy="22" r="4" fill="#38bdf8"/>
            <line x1="20" y1="18" x2="20" y2="14" stroke="#38bdf8" strokeWidth="2"/>
          </svg>
          <span className="sidebar-brand">Nexus IAM</span>
        </div>

        <nav className="sidebar-nav">
          {[
            { id: 'users', icon: '⬡', label: 'Identities' },
            { id: 'audit', icon: '◈', label: 'Audit Log' },
          ].map(item => (
            <button
              key={item.id}
              className={`nav-item ${tab === item.id ? 'active' : ''}`}
              onClick={() => setTab(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="avatar sm">{userEmail[0].toUpperCase()}</div>
            <span className="user-chip-email">{userEmail}</span>
          </div>
          <button className="btn-secondary" onClick={onLogout} style={{width:'100%',marginTop:8}}>
            Sign Out
          </button>
        </div>
      </aside>

      <main className="main-content">
        {tab === 'users' && <UsersTable />}
        {tab === 'audit' && <AuditPanel />}
      </main>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [authed, setAuthed] = useState(false);
  const [userEmail, setUserEmail] = useState('');

  useEffect(() => {
    const handler = () => { setAuthed(false); setUserEmail(''); };
    window.addEventListener('auth:expired', handler);
    return () => window.removeEventListener('auth:expired', handler);
  }, []);

  const handleLogin = (token) => {
    // Decode email from JWT payload (middle segment)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      setUserEmail(payload.email || 'user');
    } catch { setUserEmail('user'); }
    setAuthed(true);
  };

  const handleLogout = async () => {
    try { await api.logout(); } catch {}
    clearToken();
    setAuthed(false);
    setUserEmail('');
  };

  if (!authed) return <LoginScreen onLogin={handleLogin} />;
  return <Dashboard onLogout={handleLogout} userEmail={userEmail} />;
}

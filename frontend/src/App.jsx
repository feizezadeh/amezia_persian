import { useEffect, useState } from 'react';
import { apiFetch, getToken, loginWithPassword, setToken } from './api';
import { applyLocale, getInitialLocale, translate, SUPPORTED_LANGUAGES } from './i18n';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard' },
  { id: 'servers', label: 'Servers', path: '/servers' },
  { id: 'clients', label: 'Clients', path: '/clients' },
  { id: 'settings', label: 'Settings', path: '/settings' },
];

let currentLocale = getInitialLocale();

function t(text, params) {
  return translate(currentLocale, text, params);
}

const LABELS = {
  'protocols.awg': 'Amnezia WireGuard',
  'protocols.wireguard': 'WireGuard',
  'protocols.openvpn': 'OpenVPN',
  'protocols.shadowsocks': 'Shadowsocks',
  'protocols.cloak': 'Cloak',
  'protocols.ikev2': 'IKEv2',
  'protocols.openvpn_shadowsocks': 'OpenVPN + Shadowsocks',
  'protocols.openvpn_cloak': 'OpenVPN + Cloak',
  'protocols.available': 'Available protocols',
  'protocols.download': 'Download',
  'clients.qr_code': 'QR code',
};

function labelForKey(key) {
  if (!key) return t('Protocol');
  return t(LABELS[key] || key);
}

function buildShareDownloadLink(baseUrl, protocol, container) {
  if (!baseUrl) return '';
  const normalized = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
  let url = `${normalized}/download`;
  const params = new URLSearchParams();
  if (protocol) params.set('protocol', protocol);
  if (container) params.set('container', container);
  const query = params.toString();
  if (query) {
    url += `?${query}`;
  }
  return url;
}

function parseRoute() {
  const raw = window.location.hash.replace('#', '') || '/';
  const path = raw.startsWith('/') ? raw : `/${raw}`;
  const parts = path.split('/').filter(Boolean);

  if (parts.length === 0) {
    return { name: 'dashboard' };
  }

  if (parts[0] === 'dashboard') {
    return { name: 'dashboard' };
  }

  if (parts[0] === 'login') {
    return { name: 'login' };
  }

  if (parts[0] === 'servers' && parts[1] === 'new') {
    return { name: 'server-create' };
  }

  if (parts[0] === 'servers' && parts[1] && parts[2] === 'deploy') {
    return { name: 'server-deploy', id: parts[1] };
  }

  if (parts[0] === 'servers' && parts[1] && parts[2] === 'monitoring') {
    return { name: 'server-monitoring', id: parts[1] };
  }

  if (parts[0] === 'servers' && parts[1]) {
    return { name: 'server', id: parts[1] };
  }

  if (parts[0] === 'servers') {
    return { name: 'servers' };
  }

  if (parts[0] === 'clients' && parts[1]) {
    return { name: 'client', id: parts[1] };
  }

  if (parts[0] === 'clients') {
    return { name: 'clients' };
  }

  if (parts[0] === 'settings') {
    return { name: 'settings', section: parts[1] || 'profile' };
  }

  return { name: 'notfound' };
}

function useHashRoute() {
  const [route, setRoute] = useState(parseRoute());

  useEffect(() => {
    const onChange = () => setRoute(parseRoute());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const navigate = (path) => {
    window.location.hash = `#${path}`;
  };

  return { route, navigate };
}

function formatBytes(bytes) {
  if (!bytes) return '0 MB';
  const mb = bytes / 1024 / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

function formatGb(bytes) {
  if (!bytes) return '0 GB';
  const gb = bytes / 1024 / 1024 / 1024;
  return `${gb.toFixed(2)} GB`;
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleDateString(currentLocale || undefined);
}

function formatDateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(currentLocale || undefined);
}

function formatExpiry(expiresAt) {
  if (!expiresAt) {
    return { label: t('No expiration'), state: 'neutral' };
  }
  const expiry = new Date(expiresAt);
  if (Number.isNaN(expiry.getTime())) {
    return { label: expiresAt, state: 'neutral' };
  }
  const diffMs = expiry - new Date();
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
  if (diffDays < 0) {
    return { label: t('Expired'), state: 'error' };
  }
  if (diffDays <= 7) {
    return { label: t('{count} days', { count: diffDays }), state: 'warn' };
  }
  return { label: formatDate(expiresAt), state: 'neutral' };
}

function formatTrafficLimit(limitBytes, usedBytes) {
  if (!limitBytes) {
    return { label: t('Unlimited'), percent: null, state: 'neutral' };
  }
  const used = usedBytes || 0;
  const percent = Math.min(100, Math.round((used / limitBytes) * 100));
  const label = `${formatGb(used)} / ${formatGb(limitBytes)}`;
  let state = 'neutral';
  if (percent >= 100) state = 'error';
  else if (percent >= 80) state = 'warn';
  return { label, percent, state };
}

function toNumber(value) {
  const numberValue = Number(value);
  return Number.isFinite(numberValue) ? numberValue : null;
}

function parseContainers(rawContainers) {
  if (!rawContainers) return [];
  if (Array.isArray(rawContainers)) return rawContainers;
  if (typeof rawContainers === 'string') {
    try {
      const parsed = JSON.parse(rawContainers);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      return [];
    }
  }
  return [];
}

function buildProtocolRows(containers) {
  const rows = [];
  containers.forEach((containerConfig) => {
    const containerName = containerConfig.container || '';
    if (containerName === 'amnezia-awg') {
      rows.push({
        label: 'Amnezia WireGuard',
        port: containerConfig.awg?.port || '',
        transport: 'udp',
        portRange: '',
      });
    } else if (containerName === 'amnezia-wireguard') {
      rows.push({
        label: 'WireGuard',
        port: containerConfig.wireguard?.port || '',
        transport: 'udp',
        portRange: '',
      });
    } else if (containerName === 'amnezia-openvpn') {
      rows.push({
        label: 'OpenVPN',
        port: containerConfig.openvpn?.port || '',
        transport: containerConfig.openvpn?.transport_proto || 'udp',
        portRange: '',
      });
    } else if (containerName === 'amnezia-shadowsocks') {
      rows.push({
        label: 'OpenVPN',
        port: containerConfig.openvpn?.port || '',
        transport: containerConfig.openvpn?.transport_proto || 'tcp',
        portRange: '',
      });
      rows.push({
        label: 'Shadowsocks',
        port: containerConfig.shadowsocks?.port || '',
        transport: 'tcp',
        portRange: containerConfig.shadowsocks?.port_range || '',
      });
    } else if (containerName === 'amnezia-openvpn-cloak') {
      rows.push({
        label: 'OpenVPN',
        port: containerConfig.openvpn?.port || '',
        transport: containerConfig.openvpn?.transport_proto || 'tcp',
        portRange: '',
      });
      rows.push({
        label: 'Shadowsocks',
        port: containerConfig.shadowsocks?.port || '',
        transport: 'tcp',
        portRange: containerConfig.shadowsocks?.port_range || '',
      });
      rows.push({
        label: 'Cloak',
        port: containerConfig.cloak?.port || '',
        transport: 'tcp',
        portRange: '',
      });
    } else if (containerName === 'amnezia-ipsec') {
      rows.push({
        label: 'IKEv2',
        port: '500/4500',
        transport: 'udp',
        portRange: '',
      });
    }
  });
  return rows;
}

function deriveProtocolForm(containers) {
  const form = {
    awg_port: '',
    wireguard_port: '',
    openvpn_port: '',
    openvpn_proto: 'udp',
    shadowsocks_port: '',
    shadowsocks_port_range: '',
    cloak_port: '',
    cloak_shadowsocks_port_range: '',
    cloak_site: '',
  };

  containers.forEach((containerConfig) => {
    const name = containerConfig.container || '';
    if (name === 'amnezia-awg' && !form.awg_port) {
      form.awg_port = `${containerConfig.awg?.port || ''}`;
    }
    if (name === 'amnezia-wireguard' && !form.wireguard_port) {
      form.wireguard_port = `${containerConfig.wireguard?.port || ''}`;
    }
    if (name === 'amnezia-openvpn') {
      if (!form.openvpn_port) {
        form.openvpn_port = `${containerConfig.openvpn?.port || ''}`;
      }
      form.openvpn_proto = containerConfig.openvpn?.transport_proto || form.openvpn_proto;
    }
    if (name === 'amnezia-shadowsocks') {
      if (!form.shadowsocks_port) {
        form.shadowsocks_port = `${containerConfig.shadowsocks?.port || ''}`;
      }
      if (!form.shadowsocks_port_range) {
        form.shadowsocks_port_range = `${containerConfig.shadowsocks?.port_range || ''}`;
      }
    }
    if (name === 'amnezia-openvpn-cloak') {
      if (!form.cloak_port) {
        form.cloak_port = `${containerConfig.cloak?.port || ''}`;
      }
      if (!form.cloak_shadowsocks_port_range) {
        form.cloak_shadowsocks_port_range = `${containerConfig.shadowsocks?.port_range || ''}`;
      }
      if (!form.cloak_site) {
        form.cloak_site = `${containerConfig.cloak?.site || ''}`;
      }
    }
  });

  return form;
}

function Sparkline({ data, color }) {
  if (!data || data.length === 0) {
    return <div className="sparkline-empty">{t('No data')}</div>;
  }
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const points = data
    .map((value, index) => {
      const x = (index / (data.length - 1 || 1)) * 100;
      const y = 30 - ((value - min) / range) * 30;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg className="sparkline" viewBox="0 0 100 30" preserveAspectRatio="none">
      <polyline fill="none" stroke={color} strokeWidth="2" points={points} />
    </svg>
  );
}

function App() {
  const { route, navigate } = useHashRoute();
  const [token, setTokenState] = useState(getToken());
  const [locale, setLocale] = useState(() => currentLocale);
  currentLocale = locale;

  useEffect(() => {
    if (!window.location.hash) {
      navigate(token ? '/dashboard' : '/login');
    }
  }, [token, navigate]);

  useEffect(() => {
    applyLocale(locale);
  }, [locale]);

  const handleLogin = async (email, password) => {
    const authToken = await loginWithPassword(email, password);
    setToken(authToken);
    setTokenState(authToken);
    navigate('/dashboard');
  };

  const handleLogout = () => {
    setToken('');
    setTokenState('');
    navigate('/login');
  };

  const isNavActive = (itemId) => {
    if (itemId === 'servers') {
      return ['servers', 'server', 'server-create', 'server-deploy', 'server-monitoring'].includes(route.name);
    }
    if (itemId === 'clients') {
      return ['clients', 'client'].includes(route.name);
    }
    if (itemId === 'settings') {
      return route.name === 'settings';
    }
    return route.name === itemId;
  };

  if (!token) {
    return <LoginScreen locale={locale} onLocaleChange={setLocale} onLogin={handleLogin} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" />
          {t('Amnezia Control')}
        </div>
        <nav className="nav">
          {NAV_ITEMS.map((item) => (
            <a
              key={item.id}
              className={`nav-link ${isNavActive(item.id) ? 'active' : ''}`}
              href={`#${item.path}`}
            >
              <span>{t(item.label)}</span>
            </a>
          ))}
        </nav>
        <div className="form-row" style={{ marginTop: 18 }}>
          <label className="form-label">{t('Language')}</label>
          <select className="select" value={locale} onChange={(event) => setLocale(event.target.value)}>
            {SUPPORTED_LANGUAGES.map((lang) => (
              <option key={lang.code} value={lang.code}>
                {lang.nativeName} ({lang.code})
              </option>
            ))}
          </select>
        </div>
        <div style={{ marginTop: 'auto' }}>
          <button className="btn btn-ghost" type="button" onClick={handleLogout}>
            {t('Sign out')}
          </button>
        </div>
      </aside>
      <main className="content">
        {route.name === 'dashboard' && <Dashboard />}
        {route.name === 'servers' && <ServersPage />}
        {route.name === 'server-create' && <ServerCreate onCreated={(id) => navigate(`/servers/${id}`)} />}
        {route.name === 'server' && <ServerDetail serverId={route.id} />}
        {route.name === 'server-deploy' && <ServerDeploy serverId={route.id} />}
        {route.name === 'server-monitoring' && <ServerMonitoring serverId={route.id} />}
        {route.name === 'clients' && <ClientsPage />}
        {route.name === 'client' && <ClientDetail clientId={route.id} />}
        {route.name === 'settings' && <SettingsPage section={route.section} />}
        {route.name === 'notfound' && <NotFound />}
      </main>
    </div>
  );
}

function LoginScreen({ locale, onLocaleChange, onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      await onLogin(email, password);
    } catch (err) {
      setError(err.message || t('Login failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content" style={{ maxWidth: 520, margin: '0 auto' }}>
      <div className="card fade-in">
        <div className="card-header">
          <div>
            <div className="page-title">{t('Welcome back')}</div>
            <div className="subtitle">{t('Sign in to your Amnezia panel')}</div>
          </div>
          <div style={{ minWidth: 140 }}>
            <label className="form-label" style={{ marginBottom: 6 }}>
              {t('Language')}
            </label>
            <select className="select" value={locale} onChange={(event) => onLocaleChange(event.target.value)}>
              {SUPPORTED_LANGUAGES.map((lang) => (
                <option key={lang.code} value={lang.code}>
                  {lang.nativeName}
                </option>
              ))}
            </select>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="form-row">
          <label className="form-label">{t('Email')}</label>
          <input
            className="input"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="admin@example.com"
            required
          />
          <label className="form-label">{t('Password')}</label>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder={t('Password')}
            required
          />
          {error && <div className="message error">{error}</div>}
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? t('Signing in...') : t('Sign in')}
          </button>
        </form>
      </div>
    </div>
  );
}

function Dashboard() {
  const [servers, setServers] = useState([]);
  const [clients, setClients] = useState([]);
  const [expiringClients, setExpiringClients] = useState([]);
  const [overlimitClients, setOverlimitClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      apiFetch('/servers'),
      apiFetch('/clients'),
      apiFetch('/clients/expiring?days=7'),
      apiFetch('/clients/overlimit'),
    ])
      .then(([serverData, clientData, expiringData, overlimitData]) => {
        if (!active) return;
        setServers(serverData.servers || []);
        setClients(clientData.clients || []);
        setExpiringClients(expiringData.clients || []);
        setOverlimitClients(overlimitData.clients || []);
        setError('');
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || t('Failed to load dashboard'));
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const activeServers = servers.filter((server) => server.status === 'active').length;
  const activeClients = clients.filter((client) => client.status === 'active').length;

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Operations overview')}</div>
          <div className="subtitle">{t('Fast glance at your infrastructure health.')}</div>
        </div>
        <a className="btn btn-primary" href="#/servers">
          {t('Review servers')}
        </a>
      </div>

      {error && <div className="message error">{error}</div>}

      <div className="grid grid-3">
        <div className="stat lift">
          <div className="stat-label">{t('Total servers')}</div>
          <div className="stat-value">{servers.length}</div>
        </div>
        <div className="stat lift">
          <div className="stat-label">{t('Active servers')}</div>
          <div className="stat-value">{activeServers}</div>
        </div>
        <div className="stat lift">
          <div className="stat-label">{t('Active clients')}</div>
          <div className="stat-value">{activeClients}</div>
        </div>
      </div>

      <div style={{ height: 20 }} />

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Expiring clients')}</div>
            <span className="nav-pill">
              {expiringClients.length} {t('due')}
            </span>
          </div>
          {loading ? (
            <div className="hint">{t('Loading expiring clients...')}</div>
          ) : expiringClients.length === 0 ? (
            <div className="hint">{t('No clients expiring soon.')}</div>
          ) : (
            <div className="stack">
              {expiringClients.slice(0, 5).map((client) => (
                <div key={client.id} className="list-row">
                  <div>
                    <div className="card-title">{client.name}</div>
                    <div className="hint">{client.server_name}</div>
                  </div>
                  <span className="pill warn">{formatExpiry(client.expires_at).label}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Over limit')}</div>
            <span className="nav-pill">
              {overlimitClients.length} {t('alerts')}
            </span>
          </div>
          {loading ? (
            <div className="hint">{t('Loading alerts...')}</div>
          ) : overlimitClients.length === 0 ? (
            <div className="hint">{t('No clients over limit.')}</div>
          ) : (
            <div className="stack">
              {overlimitClients.slice(0, 5).map((client) => (
                <div key={client.id} className="list-row">
                  <div>
                    <div className="card-title">{client.name}</div>
                    <div className="hint">{client.server_name}</div>
                  </div>
                  <span className="pill error">{t('Over limit')}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ height: 20 }} />

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Latest servers')}</div>
            <a className="btn btn-secondary" href="#/servers">
              {t('View all')}
            </a>
          </div>
          {loading ? (
            <div className="hint">{t('Loading servers...')}</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>{t('Name')}</th>
                  <th>{t('Status')}</th>
                </tr>
              </thead>
              <tbody>
                {servers.slice(0, 4).map((server) => (
                  <tr key={server.id}>
                    <td>
                      <a className="lift" href={`#/servers/${server.id}`}>
                        {server.name}
                      </a>
                    </td>
                    <td>
                    <span className={`chip ${server.status !== 'active' ? 'pending' : ''}`}>
                      {t(server.status)}
                    </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Recent clients')}</div>
            <a className="btn btn-secondary" href="#/clients">
              {t('View all')}
            </a>
          </div>
          {loading ? (
            <div className="hint">{t('Loading clients...')}</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>{t('Name')}</th>
                  <th>{t('Status')}</th>
                </tr>
              </thead>
              <tbody>
                {clients.slice(0, 4).map((client) => (
                  <tr key={client.id}>
                    <td>
                      <a className="lift" href={`#/clients/${client.id}`}>
                        {client.name}
                      </a>
                    </td>
                    <td>
                      <span className={`chip ${client.status !== 'active' ? 'offline' : ''}`}>
                        {t(client.status)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

function ServersPage() {
  const [servers, setServers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    apiFetch('/servers')
      .then((data) => {
        if (!active) return;
        setServers(data.servers || []);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || 'Failed to load servers');
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Server fleet')}</div>
          <div className="subtitle">{t('Manage connection points and deployments.')}</div>
        </div>
        <a className="btn btn-primary" href="#/servers/new">
          {t('Add server')}
        </a>
      </div>
      {error && <div className="message error">{error}</div>}
      <div className="grid grid-2">
        {loading && <div className="hint">{t('Loading servers...')}</div>}
        {!loading &&
          servers.map((server, index) => (
            <div key={server.id} className="card lift" style={{ animationDelay: `${index * 0.05}s` }}>
              <div className="card-header">
                <div className="card-title">{server.name}</div>
                <span className={`chip ${server.status !== 'active' ? 'pending' : ''}`}>
                  {t(server.status)}
                </span>
              </div>
              <div className="hint">{server.host}</div>
              <div className="hint">
                {t('SSH')}: {server.username}@{server.host}:{server.port}
              </div>
              <div className="hint">
                {t('VPN port')}: {server.vpn_port || '—'}
              </div>
              <div style={{ height: 12 }} />
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <a className="btn btn-secondary" href={`#/servers/${server.id}`}>
                  {t('Details')}
                </a>
                <a className="btn btn-ghost" href={`#/servers/${server.id}/deploy`}>
                  {t('Deploy')}
                </a>
                <a className="btn btn-ghost" href={`#/servers/${server.id}/monitoring`}>
                  {t('Monitoring')}
                </a>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}

function ServerCreate({ onCreated }) {
  const [form, setForm] = useState({
    name: '',
    host: '',
    port: 22,
    username: 'root',
    password: '',
    vpn_subnet: '',
    default_container: 'amnezia-awg',
    awg_port: '',
    wireguard_port: '',
    openvpn_port: '',
    openvpn_proto: 'udp',
    shadowsocks_port: '',
    shadowsocks_port_range: '',
    cloak_port: '',
    cloak_shadowsocks_port_range: '',
    cloak_site: '',
  });
  const [importEnabled, setImportEnabled] = useState(false);
  const [importPanelType, setImportPanelType] = useState('');
  const [importFile, setImportFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState(false);

  const updateField = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setMessage('');
    setError(false);
    try {
      const payload = { ...form };
      const result = await apiFetch('/servers/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (importEnabled && importFile && importPanelType) {
        const formData = new FormData();
        formData.append('panel_type', importPanelType);
        formData.append('backup_file', importFile);
        await apiFetch(`/servers/${result.server_id}/import`, {
          method: 'POST',
          body: formData,
        });
      }

      setMessage(t('Server created successfully.'));
      if (onCreated) {
        onCreated(result.server_id);
      }
    } catch (err) {
      setMessage(err.message || t('Failed to create server'));
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Add new server')}</div>
          <div className="subtitle">{t('Set connection details and protocol ports before deploy.')}</div>
        </div>
      </div>

      <form className="card form-row" onSubmit={handleSubmit}>
        <div className="grid grid-2">
          <div>
            <label className="form-label">{t('Server name')}</label>
            <input className="input" value={form.name} onChange={(e) => updateField('name', e.target.value)} required />
          </div>
          <div>
            <label className="form-label">{t('Host IP / domain')}</label>
            <input className="input" value={form.host} onChange={(e) => updateField('host', e.target.value)} required />
          </div>
          <div>
            <label className="form-label">{t('SSH port')}</label>
            <input
              className="input"
              type="number"
              value={form.port}
              onChange={(e) => updateField('port', e.target.value)}
            />
          </div>
          <div>
            <label className="form-label">{t('SSH username')}</label>
            <input className="input" value={form.username} onChange={(e) => updateField('username', e.target.value)} />
          </div>
          <div>
            <label className="form-label">{t('SSH password')}</label>
            <input
              className="input"
              type="password"
              value={form.password}
              onChange={(e) => updateField('password', e.target.value)}
              required
            />
          </div>
          <div>
            <label className="form-label">{t('VPN subnet')}</label>
            <input
              className="input"
              value={form.vpn_subnet}
              onChange={(e) => updateField('vpn_subnet', e.target.value)}
              placeholder="10.8.1.0/24"
            />
          </div>
          <div>
            <label className="form-label">{t('Default protocol')}</label>
            <select
              className="select"
              value={form.default_container}
              onChange={(e) => updateField('default_container', e.target.value)}
            >
              <option value="amnezia-awg">{t('Amnezia WireGuard')}</option>
              <option value="amnezia-wireguard">{t('WireGuard')}</option>
              <option value="amnezia-openvpn">{t('OpenVPN')}</option>
              <option value="amnezia-shadowsocks">{t('OpenVPN + Shadowsocks')}</option>
              <option value="amnezia-openvpn-cloak">{t('OpenVPN + Cloak')}</option>
              <option value="amnezia-ipsec">{t('IKEv2')}</option>
            </select>
          </div>
        </div>

        <div style={{ height: 8 }} />

        <div className="card-title">{t('Protocol ports')}</div>
        <div className="grid grid-2">
          <div>
            <label className="form-label">{t('AWG port')}</label>
            <input
              className="input"
              type="number"
              value={form.awg_port}
              onChange={(e) => updateField('awg_port', e.target.value)}
              placeholder="55424"
            />
          </div>
          <div>
            <label className="form-label">{t('WireGuard port')}</label>
            <input
              className="input"
              type="number"
              value={form.wireguard_port}
              onChange={(e) => updateField('wireguard_port', e.target.value)}
              placeholder="51820"
            />
          </div>
          <div>
            <label className="form-label">{t('OpenVPN port')}</label>
            <input
              className="input"
              type="number"
              value={form.openvpn_port}
              onChange={(e) => updateField('openvpn_port', e.target.value)}
              placeholder="1194"
            />
          </div>
          <div>
            <label className="form-label">{t('OpenVPN transport')}</label>
            <select
              className="select"
              value={form.openvpn_proto}
              onChange={(e) => updateField('openvpn_proto', e.target.value)}
            >
              <option value="udp">{t('UDP')}</option>
              <option value="tcp">{t('TCP')}</option>
            </select>
          </div>
          <div>
            <label className="form-label">{t('Shadowsocks port')}</label>
            <input
              className="input"
              type="number"
              value={form.shadowsocks_port}
              onChange={(e) => updateField('shadowsocks_port', e.target.value)}
              placeholder="6789"
            />
          </div>
          <div>
            <label className="form-label">{t('Shadowsocks range')}</label>
            <input
              className="input"
              value={form.shadowsocks_port_range}
              onChange={(e) => updateField('shadowsocks_port_range', e.target.value)}
              placeholder="40000-40999"
            />
          </div>
          <div>
            <label className="form-label">{t('Cloak port')}</label>
            <input
              className="input"
              type="number"
              value={form.cloak_port}
              onChange={(e) => updateField('cloak_port', e.target.value)}
              placeholder="443"
            />
          </div>
          <div>
            <label className="form-label">{t('Cloak Shadowsocks range')}</label>
            <input
              className="input"
              value={form.cloak_shadowsocks_port_range}
              onChange={(e) => updateField('cloak_shadowsocks_port_range', e.target.value)}
              placeholder="41000-41999"
            />
          </div>
          <div className="grid-span">
            <label className="form-label">{t('Cloak fake site')}</label>
            <input
              className="input"
              value={form.cloak_site}
              onChange={(e) => updateField('cloak_site', e.target.value)}
              placeholder="tile.openstreetmap.org"
            />
          </div>
        </div>

        <div className="divider" />

        <label className="checkbox">
          <input type="checkbox" checked={importEnabled} onChange={(e) => setImportEnabled(e.target.checked)} />
          {t('Import clients from another panel')}
        </label>

        {importEnabled && (
          <div className="grid grid-2">
            <div>
              <label className="form-label">{t('Panel type')}</label>
              <select className="select" value={importPanelType} onChange={(e) => setImportPanelType(e.target.value)}>
                <option value="">{t('Select')}</option>
                <option value="wg-easy">{t('WG Easy')}</option>
                <option value="3x-ui">{t('3X-UI')}</option>
              </select>
            </div>
            <div>
              <label className="form-label">{t('Backup file')}</label>
              <input className="input" type="file" onChange={(e) => setImportFile(e.target.files?.[0] || null)} />
            </div>
          </div>
        )}

        {message && <div className={`message ${error ? 'error' : ''}`}>{message}</div>}

        <button className="btn btn-primary" type="submit" disabled={loading}>
          {loading ? t('Creating...') : t('Create server')}
        </button>
      </form>
    </div>
  );
}

function ServerDeploy({ serverId }) {
  const [server, setServer] = useState(null);
  const [logs, setLogs] = useState([{ text: t('Ready to deploy...'), type: 'info' }]);
  const [deploying, setDeploying] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    apiFetch('/servers')
      .then((data) => {
        if (!active) return;
        const found = (data.servers || []).find((item) => String(item.id) === String(serverId));
        setServer(found || null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || t('Failed to load server'));
      });
    return () => {
      active = false;
    };
  }, [serverId]);

  const appendLog = (text, type = 'info') => {
    setLogs((prev) => [...prev, { text, type }]);
  };

  const handleDeploy = async () => {
    setDeploying(true);
    setLogs([
      { text: t('📡 Connecting to server...'), type: 'info' },
      { text: t('🔧 Installing Docker...'), type: 'info' },
      { text: t('📦 Building container...'), type: 'info' },
      { text: t('🔐 Generating keys...'), type: 'info' },
      { text: t('⚙️ Configuring protocols...'), type: 'info' },
    ]);
    try {
      const data = await apiFetch(`/servers/${serverId}/deploy`, { method: 'POST' });
      if (data.success) {
        appendLog(t('✅ Deployment successful!'), 'info');
        appendLog(`${t('VPN port')}: ${data.vpn_port || '—'}`, 'info');
        if (data.public_key) {
          appendLog(`${t('Public key')}: ${data.public_key.slice(0, 40)}...`, 'info');
        }
        setTimeout(() => {
          window.location.hash = `#/servers/${serverId}`;
        }, 2000);
      } else {
        appendLog(`${t('❌ Error:')} ${data.error || t('Deployment failed')}`, 'error');
      }
    } catch (err) {
      appendLog(`${t('❌ Error:')} ${err.message || t('Deployment failed')}`, 'error');
    } finally {
      setDeploying(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Deploy server')}</div>
          <div className="subtitle">{server ? server.name : t('Preparing deployment')}</div>
        </div>
        <a className="btn btn-ghost" href={`#/servers/${serverId}`}>
          {t('Back to server')}
        </a>
      </div>

      {error && <div className="message error">{error}</div>}

      <div className="terminal">
        {logs.map((log, index) => (
          <div key={`${log.text}-${index}`} className={`terminal-line ${log.type === 'error' ? 'error' : ''}`}>
            {log.text}
          </div>
        ))}
      </div>

      <div style={{ height: 16 }} />
      <button className="btn btn-primary" type="button" onClick={handleDeploy} disabled={deploying}>
        {deploying ? t('Deploying...') : t('Start deployment')}
      </button>
    </div>
  );
}

function ServerMonitoring({ serverId }) {
  const [server, setServer] = useState(null);
  const [metrics, setMetrics] = useState([]);
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [clientsLoading, setClientsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;

    const loadAll = async () => {
      try {
        const [serverData, metricData, clientData] = await Promise.all([
          apiFetch('/servers'),
          apiFetch(`/servers/${serverId}/metrics?hours=1`),
          apiFetch(`/servers/${serverId}/client-speeds`),
        ]);

        if (!active) return;
        const found = (serverData.servers || []).find((item) => String(item.id) === String(serverId));
        setServer(found || null);
        setMetrics(metricData.metrics || []);
        setClients(clientData.clients || []);
        setError('');
      } catch (err) {
        if (!active) return;
        setError(err.message || t('Failed to load monitoring data'));
      } finally {
        if (!active) return;
        setLoading(false);
        setClientsLoading(false);
      }
    };

    loadAll();
    const interval = setInterval(loadAll, 30000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [serverId]);

  const latest = metrics[metrics.length - 1] || {};
  const cpuSeries = metrics.map((m) => Number(m.cpu_percent || 0));
  const ramSeries = metrics.map((m) => {
    if (!m.ram_total_mb) return 0;
    return (Number(m.ram_used_mb || 0) / Number(m.ram_total_mb)) * 100;
  });
  const diskSeries = metrics.map((m) => {
    if (!m.disk_total_gb) return 0;
    return (Number(m.disk_used_gb || 0) / Number(m.disk_total_gb)) * 100;
  });
  const netSeries = metrics.map((m) => Number(m.network_rx_mbps || 0) + Number(m.network_tx_mbps || 0));

  const cpuValue =
    latest.cpu_percent !== null && latest.cpu_percent !== undefined
      ? `${Number(latest.cpu_percent).toFixed(1)}%`
      : '—';
  const ramValue =
    latest.ram_total_mb !== null && latest.ram_total_mb !== undefined
      ? `${Math.round((latest.ram_used_mb / latest.ram_total_mb) * 100)}%`
      : '—';
  const diskValue =
    latest.disk_total_gb !== null && latest.disk_total_gb !== undefined
      ? `${Math.round((latest.disk_used_gb / latest.disk_total_gb) * 100)}%`
      : '—';
  const netValue =
    latest.network_rx_mbps !== null && latest.network_rx_mbps !== undefined
      ? `↓${Number(latest.network_rx_mbps).toFixed(1)} ↑${Number(latest.network_tx_mbps).toFixed(1)} Mbps`
      : '—';

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Monitoring')}</div>
          <div className="subtitle">{server ? server.name : t('Server telemetry')}</div>
        </div>
        <a className="btn btn-ghost" href={`#/servers/${serverId}`}>
          {t('Back to server')}
        </a>
      </div>

      {error && <div className="message error">{error}</div>}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('CPU usage')}</div>
            <span className="nav-pill">{cpuValue}</span>
          </div>
          {loading ? <div className="hint">{t('Loading metrics...')}</div> : <Sparkline data={cpuSeries} color="#ef4444" />}
        </div>
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('RAM usage')}</div>
            <span className="nav-pill">{ramValue}</span>
          </div>
          {loading ? <div className="hint">{t('Loading metrics...')}</div> : <Sparkline data={ramSeries} color="#f59e0b" />}
        </div>
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Disk usage')}</div>
            <span className="nav-pill">{diskValue}</span>
          </div>
          {loading ? <div className="hint">{t('Loading metrics...')}</div> : <Sparkline data={diskSeries} color="#0ea5a4" />}
        </div>
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Network throughput')}</div>
            <span className="nav-pill">{netValue}</span>
          </div>
          {loading ? <div className="hint">{t('Loading metrics...')}</div> : <Sparkline data={netSeries} color="#0284c7" />}
        </div>
      </div>

      <div style={{ height: 20 }} />

      <div className="card">
        <div className="card-header">
          <div className="card-title">{t('Client speeds')}</div>
          <span className="nav-pill">{t('Updated every 30s')}</span>
        </div>
        {clientsLoading ? (
          <div className="hint">{t('Loading clients...')}</div>
        ) : clients.length === 0 ? (
          <div className="hint">{t('No active clients found.')}</div>
        ) : (
          <div className="stack">
            {clients.map((client) => (
              <div key={client.client_id} className="list-row">
                <div>
                  <div className="card-title">{client.client_name}</div>
                  <div className="hint">{client.collected_at ? formatDateTime(client.collected_at) : '—'}</div>
                </div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  <span className={`chip ${client.status !== 'active' ? 'offline' : ''}`}>
                    {client.status ? t(client.status) : t('unknown')}
                  </span>
                  <div className="pill">
                    ↑{Number.isFinite(Number(client.speed_up_kbps)) ? Number(client.speed_up_kbps).toFixed(1) : '0'} ↓
                    {Number.isFinite(Number(client.speed_down_kbps)) ? Number(client.speed_down_kbps).toFixed(1) : '0'} KB/s
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ServerDetail({ serverId }) {
  const [server, setServer] = useState(null);
  const [clients, setClients] = useState([]);
  const [protocolRows, setProtocolRows] = useState([]);
  const [protocolForm, setProtocolForm] = useState(deriveProtocolForm([]));
  const [protocolMessage, setProtocolMessage] = useState('');
  const [protocolError, setProtocolError] = useState(false);
  const [serverMessage, setServerMessage] = useState('');
  const [serverMessageError, setServerMessageError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [clientsLoading, setClientsLoading] = useState(true);
  const [backupsLoading, setBackupsLoading] = useState(true);
  const [importsLoading, setImportsLoading] = useState(true);
  const [error, setError] = useState('');
  const [clientName, setClientName] = useState('');
  const [expiresInDays, setExpiresInDays] = useState('never');
  const [customExpires, setCustomExpires] = useState('');
  const [trafficLimit, setTrafficLimit] = useState('unlimited');
  const [customTraffic, setCustomTraffic] = useState('');
  const [creating, setCreating] = useState(false);
  const [clientMessage, setClientMessage] = useState('');
  const [clientError, setClientError] = useState(false);
  const [clientListMessage, setClientListMessage] = useState('');
  const [clientListError, setClientListError] = useState(false);
  const [backups, setBackups] = useState([]);
  const [backupMessage, setBackupMessage] = useState('');
  const [backupError, setBackupError] = useState(false);
  const [imports, setImports] = useState([]);
  const [importMessage, setImportMessage] = useState('');
  const [importError, setImportError] = useState(false);
  const [importPanelType, setImportPanelType] = useState('');
  const [importFile, setImportFile] = useState(null);
  const [syncing, setSyncing] = useState(false);

  const loadClients = async () => {
    setClientsLoading(true);
    try {
      const data = await apiFetch(`/servers/${serverId}/clients`);
      setClients(data.clients || []);
    } catch (err) {
      setError(err.message || t('Failed to load clients'));
    } finally {
      setClientsLoading(false);
    }
  };

  const loadBackups = async () => {
    setBackupsLoading(true);
    try {
      const data = await apiFetch(`/servers/${serverId}/backups`);
      setBackups(data.backups || []);
    } catch (err) {
      setBackupMessage(err.message || t('Failed to load backups'));
      setBackupError(true);
    } finally {
      setBackupsLoading(false);
    }
  };

  const loadImports = async () => {
    setImportsLoading(true);
    try {
      const data = await apiFetch(`/servers/${serverId}/imports`);
      setImports(data.imports || []);
    } catch (err) {
      setImportMessage(err.message || t('Failed to load imports'));
      setImportError(true);
    } finally {
      setImportsLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    setLoading(true);
    setClientsLoading(true);
    setError('');

    Promise.all([apiFetch('/servers'), apiFetch(`/servers/${serverId}/clients`)])
      .then(([serverData, clientData]) => {
        if (!active) return;
        const found = (serverData.servers || []).find((item) => String(item.id) === String(serverId));
        setServer(found || null);
        setClients(clientData.clients || []);
        setClientsLoading(false);
        const containers = parseContainers(found?.containers);
        let rows = buildProtocolRows(containers);
        if (!rows.length && found?.vpn_port) {
          rows = [
            {
              label: 'Amnezia WireGuard',
              port: found.vpn_port,
              transport: 'udp',
              portRange: '',
            },
          ];
        }
        setProtocolRows(rows);
        setProtocolForm(deriveProtocolForm(containers));
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || t('Failed to load server'));
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });

    loadBackups();
    loadImports();

    return () => {
      active = false;
    };
  }, [serverId]);

  const handleCreateClient = async (event) => {
    event.preventDefault();
    setCreating(true);
    setClientMessage('');
    setClientError(false);
    try {
      const trimmedName = clientName.trim().replace(/\s+/g, '_');
      if (!trimmedName) {
        setClientMessage(t('Client name is required.'));
        setClientError(true);
        return;
      }

      const payload = {
        server_id: Number(serverId),
        name: trimmedName,
      };

      let expiresDays = null;
      if (expiresInDays === 'custom') {
        const custom = Number(customExpires);
        if (!custom || custom <= 0) {
          setClientMessage(t('Enter a valid custom expiration.'));
          setClientError(true);
          return;
        }
        expiresDays = custom;
      } else if (expiresInDays !== 'never') {
        expiresDays = Number(expiresInDays);
      }
      if (expiresDays) {
        payload.expires_in_days = expiresDays;
      }

      const result = await apiFetch('/clients/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (trafficLimit !== 'unlimited' && result.client?.id) {
        let limitGb = 0;
        if (trafficLimit === 'custom') {
          limitGb = Number(customTraffic);
        } else {
          limitGb = Number(trafficLimit);
        }
        if (limitGb > 0) {
          const limitBytes = Math.round(limitGb * 1024 * 1024 * 1024);
          await apiFetch(`/clients/${result.client.id}/set-traffic-limit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ limit_bytes: limitBytes }),
          });
        }
      }

      setClientName('');
      setExpiresInDays('never');
      setCustomExpires('');
      setTrafficLimit('unlimited');
      setCustomTraffic('');
      setClientMessage(t('Client created successfully.'));
      await loadClients();
    } catch (err) {
      setClientMessage(err.message || t('Failed to create client'));
      setClientError(true);
    } finally {
      setCreating(false);
    }
  };

  const handleProtocolSubmit = async (event) => {
    event.preventDefault();
    setProtocolMessage('');
    setProtocolError(false);
    try {
      const payload = { ...protocolForm };
      const data = await apiFetch(`/servers/${serverId}/protocols/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      setProtocolMessage(data.message || t('Protocol settings updated.'));
      setProtocolError(false);
    } catch (err) {
      setProtocolMessage(err.message || t('Failed to update protocol settings'));
      setProtocolError(true);
    }
  };

  const handleSyncStats = async () => {
    setSyncing(true);
    try {
      await apiFetch(`/servers/${serverId}/sync-stats`, { method: 'POST' });
      await loadClients();
    } catch (err) {
      setError(err.message || t('Failed to sync stats'));
    } finally {
      setSyncing(false);
    }
  };

  const handleRevoke = async (clientId) => {
    setClientListMessage('');
    setClientListError(false);
    try {
      await apiFetch(`/clients/${clientId}/revoke`, { method: 'POST' });
      setClientListMessage(t('Client revoked.'));
      await loadClients();
    } catch (err) {
      setClientListMessage(err.message || t('Failed to revoke client'));
      setClientListError(true);
    }
  };

  const handleRestore = async (clientId) => {
    setClientListMessage('');
    setClientListError(false);
    try {
      await apiFetch(`/clients/${clientId}/restore`, { method: 'POST' });
      setClientListMessage(t('Client restored.'));
      await loadClients();
    } catch (err) {
      setClientListMessage(err.message || t('Failed to restore client'));
      setClientListError(true);
    }
  };

  const handleDelete = async (clientId) => {
    if (!window.confirm(t('Delete this client?'))) return;
    setClientListMessage('');
    setClientListError(false);
    try {
      await apiFetch(`/clients/${clientId}/delete`, { method: 'DELETE' });
      setClientListMessage(t('Client deleted.'));
      await loadClients();
    } catch (err) {
      setClientListMessage(err.message || t('Failed to delete client'));
      setClientListError(true);
    }
  };

  const handleCreateBackup = async () => {
    if (!window.confirm(t('Create a backup now?'))) return;
    setBackupMessage('');
    setBackupError(false);
    try {
      await apiFetch(`/servers/${serverId}/backup`, { method: 'POST' });
      setBackupMessage(t('Backup created.'));
      await loadBackups();
    } catch (err) {
      setBackupMessage(err.message || t('Failed to create backup'));
      setBackupError(true);
    }
  };

  const handleRestoreBackup = async (backupId) => {
    if (!window.confirm(t('Restore this backup?'))) return;
    setBackupMessage('');
    setBackupError(false);
    try {
      const data = await apiFetch(`/servers/${serverId}/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backup_id: backupId }),
      });
      if (data.success === false) {
        throw new Error(data.error || t('Restore failed'));
      }
      setBackupMessage(t('Restored {count} clients.', { count: data.restored || 0 }));
      await loadClients();
    } catch (err) {
      setBackupMessage(err.message || t('Failed to restore backup'));
      setBackupError(true);
    }
  };

  const handleDeleteBackup = async (backupId) => {
    if (!window.confirm(t('Delete this backup?'))) return;
    setBackupMessage('');
    setBackupError(false);
    try {
      await apiFetch(`/backups/${backupId}`, { method: 'DELETE' });
      setBackupMessage(t('Backup deleted.'));
      await loadBackups();
    } catch (err) {
      setBackupMessage(err.message || t('Failed to delete backup'));
      setBackupError(true);
    }
  };

  const handleImport = async (event) => {
    event.preventDefault();
    setImportMessage('');
    setImportError(false);

    if (!importPanelType || !importFile) {
      setImportMessage(t('Select a panel type and backup file.'));
      setImportError(true);
      return;
    }

    try {
      const formData = new FormData();
      formData.append('panel_type', importPanelType);
      formData.append('backup_file', importFile);

      const data = await apiFetch(`/servers/${serverId}/import`, {
        method: 'POST',
        body: formData,
      });

      if (!data.success) {
        throw new Error(data.error || t('Import failed'));
      }

      setImportMessage(t('Imported {count} clients.', { count: data.imported_count || 0 }));
      await loadImports();
      await loadClients();
      setImportPanelType('');
      setImportFile(null);
    } catch (err) {
      setImportMessage(err.message || t('Import failed'));
      setImportError(true);
    }
  };

  const handleDeleteServer = async () => {
    if (!window.confirm(t('Delete this server and all related data?'))) return;
    setServerMessage('');
    setServerMessageError(false);
    try {
      await apiFetch(`/servers/${serverId}/delete`, { method: 'DELETE' });
      setServerMessage(t('Server deleted. Redirecting...'));
      setTimeout(() => {
        window.location.hash = '#/servers';
      }, 1200);
    } catch (err) {
      setServerMessage(err.message || t('Failed to delete server'));
      setServerMessageError(true);
    }
  };

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{server ? server.name : t('Server detail')}</div>
          <div className="subtitle">{server ? server.host : t('Loading server info')}</div>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <a className="btn btn-secondary" href={`#/servers/${serverId}/deploy`}>
            {t('Deploy')}
          </a>
          <a className="btn btn-ghost" href={`#/servers/${serverId}/monitoring`}>
            {t('Monitoring')}
          </a>
        </div>
      </div>

      {error && <div className="message error">{error}</div>}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Server overview')}</div>
            {server && (
              <span className={`chip ${server.status !== 'active' ? 'pending' : ''}`}>
                {t(server.status)}
              </span>
            )}
          </div>
          {loading && <div className="hint">{t('Loading server data...')}</div>}
          {!loading && server && (
            <div className="form-row">
              <div>
                <div className="form-label">{t('Host')}</div>
                <div className="hint">{server.host}</div>
              </div>
              <div>
                <div className="form-label">{t('SSH')}</div>
                <div className="hint">
                  {server.username}@{server.host}:{server.port}
                </div>
              </div>
              <div>
                <div className="form-label">{t('VPN subnet')}</div>
                <div className="hint">{server.vpn_subnet || t('Auto')}</div>
              </div>
              <div>
                <div className="form-label">{t('VPN port')}</div>
                <div className="hint">{server.vpn_port || '—'}</div>
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Create client')}</div>
          </div>
          <form className="form-row" onSubmit={handleCreateClient}>
            <label className="form-label">{t('Client name')}</label>
            <input
              className="input"
              value={clientName}
              onChange={(event) => setClientName(event.target.value)}
              placeholder="mobile_user"
              required
            />
            <div className="hint">{t('Spaces are replaced with underscores.')}</div>
            <label className="form-label">{t('Expiration')}</label>
            <select
              className="select"
              value={expiresInDays}
              onChange={(event) => setExpiresInDays(event.target.value)}
            >
              <option value="never">{t('Never')}</option>
              <option value="7">{t('7 days')}</option>
              <option value="30">{t('30 days')}</option>
              <option value="60">{t('60 days')}</option>
              <option value="90">{t('90 days')}</option>
              <option value="180">{t('180 days')}</option>
              <option value="365">{t('365 days')}</option>
              <option value="custom">{t('Custom (days)')}</option>
            </select>
            {expiresInDays === 'custom' && (
              <input
                className="input"
                type="number"
                min="1"
                value={customExpires}
                onChange={(event) => setCustomExpires(event.target.value)}
                placeholder={t('Days')}
              />
            )}
            <label className="form-label">{t('Traffic limit')}</label>
            <select
              className="select"
              value={trafficLimit}
              onChange={(event) => setTrafficLimit(event.target.value)}
            >
              <option value="unlimited">{t('Unlimited')}</option>
              <option value="1">1 GB</option>
              <option value="5">5 GB</option>
              <option value="10">10 GB</option>
              <option value="25">25 GB</option>
              <option value="50">50 GB</option>
              <option value="100">100 GB</option>
              <option value="250">250 GB</option>
              <option value="500">500 GB</option>
              <option value="1000">1000 GB</option>
              <option value="custom">{t('Custom (GB)')}</option>
            </select>
            {trafficLimit === 'custom' && (
              <input
                className="input"
                type="number"
                min="1"
                value={customTraffic}
                onChange={(event) => setCustomTraffic(event.target.value)}
                placeholder="GB"
              />
            )}
            {clientMessage && <div className={`message ${clientError ? 'error' : ''}`}>{clientMessage}</div>}
            <button className="btn btn-primary" type="submit" disabled={creating}>
              {creating ? t('Creating...') : t('Create client')}
            </button>
          </form>
        </div>
      </div>

      <div style={{ height: 20 }} />

      <div className="card">
        <div className="card-header">
          <div className="card-title">{t('Protocol settings')}</div>
          <span className="nav-pill">{t('Redeploy to apply')}</span>
        </div>
        {protocolRows.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>{t('Protocol')}</th>
                <th>{t('Port')}</th>
                <th>{t('Transport')}</th>
                <th>{t('Range')}</th>
              </tr>
            </thead>
            <tbody>
              {protocolRows.map((row, index) => (
                <tr key={`${row.label}-${index}`}>
                  <td>{t(row.label)}</td>
                  <td>{row.port || '—'}</td>
                  <td>{row.transport || '—'}</td>
                  <td>{row.portRange || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="hint">{t('Protocol data will appear after deployment.')}</div>
        )}
        <div style={{ height: 16 }} />
        <form className="grid grid-2 form-row" onSubmit={handleProtocolSubmit}>
          <div>
            <label className="form-label">{t('AWG port')}</label>
            <input
              className="input"
              type="number"
              value={protocolForm.awg_port}
              onChange={(event) => setProtocolForm({ ...protocolForm, awg_port: event.target.value })}
              placeholder="55424"
            />
          </div>
          <div>
            <label className="form-label">{t('WireGuard port')}</label>
            <input
              className="input"
              type="number"
              value={protocolForm.wireguard_port}
              onChange={(event) => setProtocolForm({ ...protocolForm, wireguard_port: event.target.value })}
              placeholder="51820"
            />
          </div>
          <div>
            <label className="form-label">{t('OpenVPN port')}</label>
            <input
              className="input"
              type="number"
              value={protocolForm.openvpn_port}
              onChange={(event) => setProtocolForm({ ...protocolForm, openvpn_port: event.target.value })}
              placeholder="1194"
            />
          </div>
          <div>
            <label className="form-label">{t('OpenVPN transport')}</label>
            <select
              className="select"
              value={protocolForm.openvpn_proto}
              onChange={(event) => setProtocolForm({ ...protocolForm, openvpn_proto: event.target.value })}
            >
              <option value="udp">{t('UDP')}</option>
              <option value="tcp">{t('TCP')}</option>
            </select>
          </div>
          <div>
            <label className="form-label">{t('Shadowsocks port')}</label>
            <input
              className="input"
              type="number"
              value={protocolForm.shadowsocks_port}
              onChange={(event) => setProtocolForm({ ...protocolForm, shadowsocks_port: event.target.value })}
              placeholder="6789"
            />
          </div>
          <div>
            <label className="form-label">{t('Shadowsocks port range')}</label>
            <input
              className="input"
              value={protocolForm.shadowsocks_port_range}
              onChange={(event) => setProtocolForm({ ...protocolForm, shadowsocks_port_range: event.target.value })}
              placeholder="40000-40999"
            />
          </div>
          <div>
            <label className="form-label">{t('Cloak port')}</label>
            <input
              className="input"
              type="number"
              value={protocolForm.cloak_port}
              onChange={(event) => setProtocolForm({ ...protocolForm, cloak_port: event.target.value })}
              placeholder="443"
            />
          </div>
          <div>
            <label className="form-label">{t('Cloak Shadowsocks range')}</label>
            <input
              className="input"
              value={protocolForm.cloak_shadowsocks_port_range}
              onChange={(event) => setProtocolForm({ ...protocolForm, cloak_shadowsocks_port_range: event.target.value })}
              placeholder="41000-41999"
            />
          </div>
          <div className="grid-span">
            <label className="form-label">{t('Cloak fake site')}</label>
            <input
              className="input"
              value={protocolForm.cloak_site}
              onChange={(event) => setProtocolForm({ ...protocolForm, cloak_site: event.target.value })}
              placeholder="tile.openstreetmap.org"
            />
          </div>
          {protocolMessage && <div className={`message ${protocolError ? 'error' : ''}`}>{protocolMessage}</div>}
          <button className="btn btn-primary" type="submit">
            {t('Save protocol settings')}
          </button>
        </form>
      </div>

      <div style={{ height: 20 }} />

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Backups')}</div>
            <button className="btn btn-secondary" type="button" onClick={handleCreateBackup}>
              {t('Create backup')}
            </button>
          </div>
          {backupsLoading ? (
            <div className="hint">{t('Loading backups...')}</div>
          ) : backups.length === 0 ? (
            <div className="hint">{t('No backups yet.')}</div>
          ) : (
            <div className="stack">
              {backups.map((backup) => (
                <div key={backup.id} className="list-row">
                  <div>
                    <div className="card-title">{backup.backup_name}</div>
                    <div className="hint">
                      {backup.clients_count} {t('clients')} • {formatGb(backup.backup_size)} • {formatDateTime(backup.created_at)}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {backup.status === 'completed' && (
                      <button className="btn btn-ghost" type="button" onClick={() => handleRestoreBackup(backup.id)}>
                        {t('Restore')}
                      </button>
                    )}
                    <button className="btn btn-ghost" type="button" onClick={() => handleDeleteBackup(backup.id)}>
                      {t('Delete')}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          {backupMessage && <div className={`message ${backupError ? 'error' : ''}`}>{backupMessage}</div>}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Import from panel')}</div>
          </div>
          <form className="form-row" onSubmit={handleImport}>
            <label className="form-label">{t('Panel type')}</label>
            <select
              className="select"
              value={importPanelType}
              onChange={(event) => setImportPanelType(event.target.value)}
            >
              <option value="">{t('Select')}</option>
              <option value="wg-easy">{t('WG Easy')}</option>
              <option value="3x-ui">{t('3X-UI')}</option>
            </select>
            <label className="form-label">{t('Backup file')}</label>
            <input
              className="input"
              type="file"
              onChange={(event) => setImportFile(event.target.files?.[0] || null)}
            />
            <button className="btn btn-secondary" type="submit">
              {t('Import clients')}
            </button>
            {importMessage && <div className={`message ${importError ? 'error' : ''}`}>{importMessage}</div>}
          </form>
          <div style={{ height: 12 }} />
          <div className="card-title">{t('Import history')}</div>
          {importsLoading ? (
            <div className="hint">{t('Loading history...')}</div>
          ) : imports.length === 0 ? (
            <div className="hint">{t('No imports yet.')}</div>
          ) : (
            <div className="stack">
              {imports.map((item) => (
                <div key={item.id} className="list-row">
                  <div>
                    <div className="card-title">{item.panel_type}</div>
                    <div className="hint">
                      {item.imported_count} {t('clients')} • {formatDateTime(item.created_at)}
                    </div>
                  </div>
                  <span className={`chip ${item.status !== 'success' ? 'pending' : ''}`}>{item.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ height: 20 }} />

      <div className="card">
        <div className="card-header">
          <div className="card-title">{t('Client list')}</div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn btn-ghost" type="button" onClick={handleSyncStats} disabled={syncing}>
              {syncing ? t('Syncing...') : t('Sync stats')}
            </button>
            <span className="nav-pill">
              {clients.length} {t('clients')}
            </span>
          </div>
        </div>
        {clientListMessage && (
          <div className={`message ${clientListError ? 'error' : ''}`}>{clientListMessage}</div>
        )}
        {clientsLoading ? (
          <div className="hint">{t('Loading clients...')}</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t('Name')}</th>
                <th>{t('IP')}</th>
                <th>{t('Status')}</th>
                <th>{t('Expiration')}</th>
                <th>{t('Traffic')}</th>
                <th>{t('Limit')}</th>
                <th>{t('Last handshake')}</th>
                <th>{t('Actions')}</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => {
                const expiry = formatExpiry(client.expires_at);
                const traffic = formatTrafficLimit(
                  client.traffic_limit,
                  (client.bytes_sent || 0) + (client.bytes_received || 0)
                );
                return (
                  <tr key={client.id}>
                    <td>
                      <a href={`#/clients/${client.id}`}>{client.name}</a>
                    </td>
                    <td>{client.client_ip}</td>
                    <td>
                      <span className={`chip ${client.status !== 'active' ? 'offline' : ''}`}>
                        {t(client.status)}
                      </span>
                    </td>
                    <td>
                      <span className={`pill ${expiry.state}`}>{expiry.label}</span>
                    </td>
                    <td>{formatBytes((client.bytes_sent || 0) + (client.bytes_received || 0))}</td>
                    <td>
                      <div className={`pill ${traffic.state}`}>{traffic.label}</div>
                      {traffic.percent !== null && (
                        <div className="progress">
                          <span style={{ width: `${traffic.percent}%` }} />
                        </div>
                      )}
                    </td>
                    <td>{client.last_handshake || t('Never')}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {client.status === 'active' ? (
                          <button className="btn btn-ghost" type="button" onClick={() => handleRevoke(client.id)}>
                            {t('Revoke')}
                          </button>
                        ) : (
                          <button className="btn btn-ghost" type="button" onClick={() => handleRestore(client.id)}>
                            {t('Restore')}
                          </button>
                        )}
                        <button className="btn btn-ghost" type="button" onClick={() => handleDelete(client.id)}>
                          {t('Delete')}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div style={{ height: 20 }} />

      <div className="card muted-card">
        <div className="card-header">
          <div className="card-title">{t('Danger zone')}</div>
        </div>
        <div className="form-row">
          <div className="hint">
            {t('Deleting a server removes all deployment data, containers, and client configs.')}
          </div>
          <button className="btn btn-danger" type="button" onClick={handleDeleteServer}>
            {t('Delete server')}
          </button>
          {serverMessage && (
            <div className={`message ${serverMessageError ? 'error' : ''}`}>{serverMessage}</div>
          )}
        </div>
      </div>
    </div>
  );
}

function ClientsPage() {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    apiFetch('/clients')
      .then((data) => {
        if (!active) return;
        setClients(data.clients || []);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || t('Failed to load clients'));
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Client registry')}</div>
          <div className="subtitle">{t('Track user access and active devices.')}</div>
        </div>
      </div>
      {error && <div className="message error">{error}</div>}
      <div className="card">
        {loading ? (
          <div className="hint">{t('Loading clients...')}</div>
        ) : (
        <table className="table">
          <thead>
            <tr>
              <th>{t('Name')}</th>
              <th>{t('Server')}</th>
              <th>{t('Status')}</th>
              <th>{t('Traffic')}</th>
              <th>{t('Expiration')}</th>
            </tr>
          </thead>
          <tbody>
            {clients.map((client) => (
              <tr key={client.id}>
                <td>
                  <a href={`#/clients/${client.id}`}>{client.name}</a>
                </td>
                <td>{client.server_name}</td>
                <td>
                  <span className={`chip ${client.status !== 'active' ? 'offline' : ''}`}>
                    {t(client.status)}
                  </span>
                </td>
                <td>{formatBytes((client.bytes_sent || 0) + (client.bytes_received || 0))}</td>
                <td>{formatExpiry(client.expires_at).label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
    </div>
  );
}

function ClientDetail({ clientId }) {
  const [client, setClient] = useState(null);
  const [protocolGroups, setProtocolGroups] = useState([]);
  const [qrCodes, setQrCodes] = useState([]);
  const [shareUrl, setShareUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMessage, setActionMessage] = useState('');
  const [actionError, setActionError] = useState(false);
  const [shareMessage, setShareMessage] = useState('');
  const [shareError, setShareError] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    apiFetch(`/clients/${clientId}/details`)
      .then((data) => {
        if (!active) return;
        setClient(data.client || null);
        setProtocolGroups(data.protocol_groups || []);
        setQrCodes(data.qr_codes || []);
        setShareUrl(data.share_url || '');
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || t('Failed to load client'));
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [clientId]);

  const refreshClient = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch(`/clients/${clientId}/details`);
      setClient(data.client || null);
      setProtocolGroups(data.protocol_groups || []);
      setQrCodes(data.qr_codes || []);
      setShareUrl(data.share_url || '');
    } catch (err) {
      setError(err.message || t('Failed to load client'));
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async () => {
    if (!client) return;
    setActionLoading(true);
    setActionMessage('');
    setActionError(false);
    try {
      await apiFetch(`/clients/${clientId}/revoke`, { method: 'POST' });
      setActionMessage(t('Client access revoked.'));
      await refreshClient();
    } catch (err) {
      setActionMessage(err.message || t('Failed to revoke client'));
      setActionError(true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRestore = async () => {
    if (!client) return;
    setActionLoading(true);
    setActionMessage('');
    setActionError(false);
    try {
      await apiFetch(`/clients/${clientId}/restore`, { method: 'POST' });
      setActionMessage(t('Client access restored.'));
      await refreshClient();
    } catch (err) {
      setActionMessage(err.message || t('Failed to restore client'));
      setActionError(true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteClient = async () => {
    if (!client) return;
    if (!window.confirm(t('Delete this client?'))) return;
    setActionLoading(true);
    setActionMessage('');
    setActionError(false);
    try {
      await apiFetch(`/clients/${clientId}/delete`, { method: 'DELETE' });
      setActionMessage(t('Client deleted. Redirecting...'));
      setTimeout(() => {
        window.location.hash = '#/clients';
      }, 1200);
    } catch (err) {
      setActionMessage(err.message || t('Failed to delete client'));
      setActionError(true);
    } finally {
      setActionLoading(false);
    }
  };

  const handleCopyShare = async () => {
    if (!shareUrl) return;
    setShareMessage('');
    setShareError(false);
    try {
      await navigator.clipboard.writeText(shareUrl);
      setShareMessage(t('Share link copied.'));
    } catch (err) {
      setShareMessage(t('Copy failed. Please copy manually.'));
      setShareError(true);
    }
  };

  const downloadAllLink = buildShareDownloadLink(shareUrl);

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{client ? client.name : t('Client detail')}</div>
          <div className="subtitle">{client ? client.client_ip : t('Loading client info')}</div>
        </div>
      </div>
      {error && <div className="message error">{error}</div>}
      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Connection status')}</div>
          </div>
          {loading && <div className="hint">{t('Loading client data...')}</div>}
          {client && (
            <div className="form-row">
              <div>
                <div className="form-label">{t('Status')}</div>
                <span className={`chip ${client.status !== 'active' ? 'offline' : ''}`}>
                  {t(client.status)}
                </span>
              </div>
              <div>
                <div className="form-label">{t('Uploaded')}</div>
                <div className="hint">{formatBytes(client.bytes_sent || 0)}</div>
              </div>
              <div>
                <div className="form-label">{t('Downloaded')}</div>
                <div className="hint">{formatBytes(client.bytes_received || 0)}</div>
              </div>
              <div>
                <div className="form-label">{t('Last handshake')}</div>
                <div className="hint">{client.last_handshake || t('Never')}</div>
              </div>
              <div>
                <div className="form-label">{t('Expiration')}</div>
                <div className="hint">{formatExpiry(client.expires_at).label}</div>
              </div>
              <div>
                <div className="form-label">{t('Traffic limit')}</div>
                <div className="hint">
                  {formatTrafficLimit(
                    client.traffic_limit,
                    (client.bytes_sent || 0) + (client.bytes_received || 0)
                  ).label}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Actions & sharing')}</div>
          </div>
          <div className="form-row">
            <div className="form-label">{t('Share link')}</div>
            {shareUrl ? (
              <input className="input" value={shareUrl} readOnly />
            ) : (
              <div className="hint">{t('Share link not available yet.')}</div>
            )}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button className="btn btn-secondary" type="button" onClick={handleCopyShare} disabled={!shareUrl}>
                {t('Copy link')}
              </button>
              {shareUrl && (
                <a className="btn btn-ghost" href={shareUrl} target="_blank" rel="noreferrer">
                  {t('Open share page')}
                </a>
              )}
            </div>
            {shareMessage && <div className={`message ${shareError ? 'error' : ''}`}>{shareMessage}</div>}
            <div className="form-label">{t('Client access')}</div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {client && client.status === 'active' ? (
                <button className="btn btn-secondary" type="button" onClick={handleRevoke} disabled={actionLoading}>
                  {actionLoading ? t('Revoking...') : t('Revoke access')}
                </button>
              ) : (
                <button className="btn btn-primary" type="button" onClick={handleRestore} disabled={actionLoading}>
                  {actionLoading ? t('Restoring...') : t('Restore access')}
                </button>
              )}
              <button className="btn btn-danger" type="button" onClick={handleDeleteClient} disabled={actionLoading}>
                {t('Delete client')}
              </button>
            </div>
            {actionMessage && <div className={`message ${actionError ? 'error' : ''}`}>{actionMessage}</div>}
          </div>
        </div>
      </div>

      <div style={{ height: 20 }} />

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('QR codes')}</div>
          </div>
          {loading && <div className="hint">{t('Loading QR codes...')}</div>}
          {!loading && qrCodes.length === 0 && (
            <div className="hint">{t('No QR codes generated yet.')}</div>
          )}
          {!loading && qrCodes.length > 0 && (
            <div className="grid grid-2">
              {qrCodes.map((item, index) => (
                <div key={item.label_key || item.label || index} className="stat">
                  <div className="form-label">{item.label || labelForKey(item.label_key)}</div>
                  <img
                    src={item.qr}
                    alt={item.label || t('QR code')}
                    style={{ width: '100%', maxWidth: 220, marginTop: 12 }}
                  />
                </div>
              ))}
            </div>
          )}
          <div className="hint" style={{ marginTop: 12 }}>
            {t('Scan with the Amnezia VPN app.')}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Protocol downloads')}</div>
          </div>
          {shareUrl ? (
            <div className="form-row">
              <a className="btn btn-primary" href={downloadAllLink}>
                {t('Download full config')}
              </a>
            </div>
          ) : (
            <div className="hint">{t('Generate a share link to access downloads.')}</div>
          )}
          {!loading && protocolGroups.length === 0 && (
            <div className="hint">{t('No protocol-specific configs available.')}</div>
          )}
          {!loading &&
            shareUrl &&
            protocolGroups.map((group) => (
              <div key={group.title_key} className="stat" style={{ marginTop: 16 }}>
                <div className="form-label">{labelForKey(group.title_key)}</div>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 10 }}>
                  {group.items.map((item) => {
                    const link = buildShareDownloadLink(shareUrl, item.protocol, item.container);
                    const label = labelForKey(item.label_key);
                    return (
                      <a key={`${item.protocol}-${item.container || 'default'}`} className="btn btn-secondary" href={link}>
                        {label}
                      </a>
                    );
                  })}
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

function SettingsPage({ section }) {
  const [activeTab, setActiveTab] = useState(section || 'profile');
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [messageError, setMessageError] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });
  const [apiKey, setApiKey] = useState('');
  const [skipTest, setSkipTest] = useState(false);
  const [translations, setTranslations] = useState([]);
  const [users, setUsers] = useState([]);
  const [userForm, setUserForm] = useState({ name: '', email: '', password: '', role: 'user' });
  const [ldapConfig, setLdapConfig] = useState({
    enabled: false,
    host: '',
    port: 389,
    use_tls: false,
    base_dn: '',
    bind_dn: '',
    bind_password: '',
    user_search_filter: '(uid=%s)',
    group_search_filter: '(memberUid=%s)',
    sync_interval: 30,
  });
  const [ldapMappings, setLdapMappings] = useState([]);
  const [ldapLoaded, setLdapLoaded] = useState(false);

  useEffect(() => {
    setActiveTab(section || 'profile');
  }, [section]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    apiFetch('/settings')
      .then((data) => {
        if (!active) return;
        setSettings(data);
        setApiKey(data.openrouter_key || '');
        setTranslations(data.translation_stats || []);
        setUsers(data.users || []);
      })
      .catch((err) => {
        if (!active) return;
        setMessage(err.message || t('Failed to load settings'));
        setMessageError(true);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const isAdmin = settings?.user?.role === 'admin';

  const switchTab = (tab) => {
    setActiveTab(tab);
    window.location.hash = `#/settings/${tab}`;
  };

  const handlePasswordChange = async (event) => {
    event.preventDefault();
    setMessage('');
    setMessageError(false);
    try {
      await apiFetch('/settings/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(passwordForm),
      });
      setMessage(t('Password updated.'));
      setPasswordForm({ current_password: '', new_password: '', confirm_password: '' });
    } catch (err) {
      setMessage(err.message || t('Failed to update password'));
      setMessageError(true);
    }
  };

  const handleApiKeySave = async (event) => {
    event.preventDefault();
    setMessage('');
    setMessageError(false);
    try {
      await apiFetch('/settings/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: 'openrouter', api_key: apiKey, skip_test: skipTest }),
      });
      setMessage(t('API key saved.'));
    } catch (err) {
      setMessage(err.message || t('Failed to save API key'));
      setMessageError(true);
    }
  };

  const handleTranslate = async (code) => {
    setMessage('');
    setMessageError(false);
    try {
      await apiFetch('/translations/auto-translate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language: code }),
      });
      const data = await apiFetch('/translations/stats');
      setTranslations(data.stats || []);
      setMessage(t('Translation updated.'));
    } catch (err) {
      setMessage(err.message || t('Translation failed'));
      setMessageError(true);
    }
  };

  const handleAddUser = async (event) => {
    event.preventDefault();
    setMessage('');
    setMessageError(false);
    try {
      await apiFetch('/settings/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userForm),
      });
      const data = await apiFetch('/settings');
      setUsers(data.users || []);
      setUserForm({ name: '', email: '', password: '', role: 'user' });
      setMessage(t('User added.'));
    } catch (err) {
      setMessage(err.message || t('Failed to add user'));
      setMessageError(true);
    }
  };

  const handleDeleteUser = async (userId) => {
    setMessage('');
    setMessageError(false);
    try {
      await apiFetch(`/settings/users/${userId}`, { method: 'DELETE' });
      const data = await apiFetch('/settings');
      setUsers(data.users || []);
      setMessage(t('User deleted.'));
    } catch (err) {
      setMessage(err.message || t('Failed to delete user'));
      setMessageError(true);
    }
  };

  const loadLdap = async () => {
    if (ldapLoaded) return;
    try {
      const data = await apiFetch('/settings/ldap');
      setLdapConfig({
        enabled: Boolean(data.config?.enabled),
        host: data.config?.host || '',
        port: data.config?.port || 389,
        use_tls: Boolean(data.config?.use_tls),
        base_dn: data.config?.base_dn || '',
        bind_dn: data.config?.bind_dn || '',
        bind_password: data.config?.bind_password || '',
        user_search_filter: data.config?.user_search_filter || '(uid=%s)',
        group_search_filter: data.config?.group_search_filter || '(memberUid=%s)',
        sync_interval: data.config?.sync_interval || 30,
      });
      setLdapMappings(data.mappings || []);
      setLdapLoaded(true);
    } catch (err) {
      setMessage(err.message || t('Failed to load LDAP settings'));
      setMessageError(true);
    }
  };

  useEffect(() => {
    if (activeTab === 'ldap' && isAdmin) {
      loadLdap();
    }
  }, [activeTab, isAdmin]);

  const handleSaveLdap = async (event) => {
    event.preventDefault();
    setMessage('');
    setMessageError(false);
    try {
      await apiFetch('/settings/ldap/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ldapConfig),
      });
      setMessage(t('LDAP settings saved.'));
    } catch (err) {
      setMessage(err.message || t('Failed to save LDAP settings'));
      setMessageError(true);
    }
  };

  const handleTestLdap = async () => {
    setMessage('');
    setMessageError(false);
    try {
      const data = await apiFetch('/settings/ldap/test', { method: 'POST' });
      setMessage(data.message || (data.success ? t('LDAP connected.') : t('LDAP test failed.')));
      setMessageError(!data.success);
    } catch (err) {
      setMessage(err.message || t('LDAP test failed.'));
      setMessageError(true);
    }
  };

  if (loading) {
    return <div className="hint">{t('Loading settings...')}</div>;
  }

  return (
    <div className="fade-in">
      <div className="topbar">
        <div>
          <div className="page-title">{t('Settings')}</div>
          <div className="subtitle">{t('Manage profile, tokens, and translations.')}</div>
        </div>
      </div>

      <div className="tabs">
        <button className={`tab ${activeTab === 'profile' ? 'active' : ''}`} onClick={() => switchTab('profile')}>
          {t('Profile')}
        </button>
        <button className={`tab ${activeTab === 'api' ? 'active' : ''}`} onClick={() => switchTab('api')}>
          {t('API Keys')}
        </button>
        <button
          className={`tab ${activeTab === 'translations' ? 'active' : ''}`}
          onClick={() => switchTab('translations')}
        >
          {t('Translations')}
        </button>
        {isAdmin && (
          <button className={`tab ${activeTab === 'users' ? 'active' : ''}`} onClick={() => switchTab('users')}>
            {t('Users')}
          </button>
        )}
        {isAdmin && (
          <button className={`tab ${activeTab === 'ldap' ? 'active' : ''}`} onClick={() => switchTab('ldap')}>
            {t('LDAP')}
          </button>
        )}
      </div>

      {message && <div className={`message ${messageError ? 'error' : ''}`}>{message}</div>}

      {activeTab === 'profile' && (
        <div className="card form-row">
          <div className="card-title">{t('Change password')}</div>
          <form className="form-row" onSubmit={handlePasswordChange}>
            <input
              className="input"
              type="password"
              placeholder={t('Current password')}
              value={passwordForm.current_password}
              onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
            />
            <input
              className="input"
              type="password"
              placeholder={t('New password')}
              value={passwordForm.new_password}
              onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
            />
            <input
              className="input"
              type="password"
              placeholder={t('Confirm new password')}
              value={passwordForm.confirm_password}
              onChange={(e) => setPasswordForm({ ...passwordForm, confirm_password: e.target.value })}
            />
            <button className="btn btn-primary" type="submit">
              {t('Update password')}
            </button>
          </form>
        </div>
      )}

      {activeTab === 'api' && (
        <div className="card form-row">
          <div className="card-title">{t('OpenRouter API key')}</div>
          <form className="form-row" onSubmit={handleApiKeySave}>
            <input
              className="input"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-or-v1-..."
            />
            <label className="checkbox">
              <input type="checkbox" checked={skipTest} onChange={(e) => setSkipTest(e.target.checked)} />
              {t('Skip validation')}
            </label>
            <button className="btn btn-primary" type="submit">
              {t('Save key')}
            </button>
          </form>
        </div>
      )}

      {activeTab === 'translations' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">{t('Translation status')}</div>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>{t('Language')}</th>
                <th>{t('Progress')}</th>
                <th>{t('Action')}</th>
              </tr>
            </thead>
            <tbody>
              {translations.map((stat) => {
                const percent = stat.total_count
                  ? Math.round((stat.translated_count / stat.total_count) * 100)
                  : 0;
                return (
                  <tr key={stat.code}>
                    <td>{stat.name} ({stat.code})</td>
                    <td>
                      <div className="progress">
                        <span style={{ width: `${percent}%` }} />
                      </div>
                      <div className="hint">{percent}%</div>
                    </td>
                    <td>
                      {stat.code !== 'en' && stat.translated_count < stat.total_count && (
                        <button className="btn btn-ghost" type="button" onClick={() => handleTranslate(stat.code)}>
                          {t('Auto translate')}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'users' && isAdmin && (
        <div className="grid grid-2">
          <div className="card form-row">
            <div className="card-title">{t('Add user')}</div>
            <form className="form-row" onSubmit={handleAddUser}>
              <input
                className="input"
                placeholder={t('Name')}
                value={userForm.name}
                onChange={(e) => setUserForm({ ...userForm, name: e.target.value })}
              />
              <input
                className="input"
                placeholder={t('Email')}
                value={userForm.email}
                onChange={(e) => setUserForm({ ...userForm, email: e.target.value })}
              />
              <input
                className="input"
                type="password"
                placeholder={t('Password')}
                value={userForm.password}
                onChange={(e) => setUserForm({ ...userForm, password: e.target.value })}
              />
              <select
                className="select"
                value={userForm.role}
                onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}
              >
                <option value="user">{t('User')}</option>
                <option value="admin">{t('Admin')}</option>
              </select>
              <button className="btn btn-primary" type="submit">
                {t('Add user')}
              </button>
            </form>
          </div>

          <div className="card">
            <div className="card-header">
              <div className="card-title">{t('Users')}</div>
            </div>
            {users.length === 0 ? (
              <div className="hint">{t('No users found.')}</div>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('Name')}</th>
                    <th>{t('Email')}</th>
                    <th>{t('Role')}</th>
                    <th>{t('Created')}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>{u.name}</td>
                      <td>{u.email}</td>
                      <td>{u.role}</td>
                      <td>{formatDate(u.created_at)}</td>
                      <td>
                        {settings?.user?.id !== u.id && (
                          <button className="btn btn-ghost" type="button" onClick={() => handleDeleteUser(u.id)}>
                            {t('Delete')}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {activeTab === 'ldap' && isAdmin && (
        <div className="grid grid-2">
          <div className="card form-row">
            <div className="card-header">
              <div className="card-title">{t('LDAP configuration')}</div>
              <button className="btn btn-ghost" type="button" onClick={handleTestLdap}>
                {t('Test connection')}
              </button>
            </div>
            <form className="form-row" onSubmit={handleSaveLdap}>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={ldapConfig.enabled}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, enabled: e.target.checked })}
                />
                {t('Enable LDAP authentication')}
              </label>
              <input
                className="input"
                placeholder={t('Host')}
                value={ldapConfig.host}
                onChange={(e) => setLdapConfig({ ...ldapConfig, host: e.target.value })}
              />
              <input
                className="input"
                type="number"
                placeholder={t('Port')}
                value={ldapConfig.port}
                onChange={(e) => setLdapConfig({ ...ldapConfig, port: e.target.value })}
              />
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={ldapConfig.use_tls}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, use_tls: e.target.checked })}
                />
                {t('Use TLS (LDAPS)')}
              </label>
              <input
                className="input"
                placeholder={t('Base DN')}
                value={ldapConfig.base_dn}
                onChange={(e) => setLdapConfig({ ...ldapConfig, base_dn: e.target.value })}
              />
              <input
                className="input"
                placeholder={t('Bind DN')}
                value={ldapConfig.bind_dn}
                onChange={(e) => setLdapConfig({ ...ldapConfig, bind_dn: e.target.value })}
              />
              <input
                className="input"
                type="password"
                placeholder={t('Bind password')}
                value={ldapConfig.bind_password}
                onChange={(e) => setLdapConfig({ ...ldapConfig, bind_password: e.target.value })}
              />
              <input
                className="input"
                placeholder={t('User search filter')}
                value={ldapConfig.user_search_filter}
                onChange={(e) => setLdapConfig({ ...ldapConfig, user_search_filter: e.target.value })}
              />
              <input
                className="input"
                placeholder={t('Group search filter')}
                value={ldapConfig.group_search_filter}
                onChange={(e) => setLdapConfig({ ...ldapConfig, group_search_filter: e.target.value })}
              />
              <input
                className="input"
                type="number"
                placeholder={t('Sync interval')}
                value={ldapConfig.sync_interval}
                onChange={(e) => setLdapConfig({ ...ldapConfig, sync_interval: e.target.value })}
              />
              <button className="btn btn-primary" type="submit">
                {t('Save LDAP settings')}
              </button>
            </form>
          </div>

          <div className="card">
            <div className="card-header">
              <div className="card-title">{t('Group mappings')}</div>
            </div>
            {ldapMappings.length === 0 ? (
              <div className="hint">{t('No mappings configured.')}</div>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('Group')}</th>
                    <th>{t('Role')}</th>
                    <th>{t('Description')}</th>
                  </tr>
                </thead>
                <tbody>
                  {ldapMappings.map((mapping) => (
                    <tr key={mapping.id || mapping.ldap_group}>
                      <td>{mapping.ldap_group}</td>
                      <td>{mapping.role_name}</td>
                      <td>{mapping.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function NotFound() {
  return (
    <div className="card">
      <div className="card-title">{t('Page not found')}</div>
      <p className="hint">{t('Use the navigation to return to a valid page.')}</p>
    </div>
  );
}

export default App;

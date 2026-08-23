import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LogOut, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "./api/client";
import { useAuth } from "./useAuth.js";
import { useToast } from "./components/useToast.js";
import DashboardHeader from "./components/DashboardHeader.jsx";
import DeviceTable from "./components/DeviceTable.jsx";
import EnrollDeviceForm from "./components/EnrollDeviceForm.jsx";
import DeviceDetailPanel from "./components/DeviceDetailPanel.jsx";
import ConfirmActionModal from "./components/ConfirmActionModal.jsx";
import LogsPage from "./LogsPage.jsx";
import LoginPage from "./LoginPage.jsx";

const APP_ID = import.meta.env.VITE_ALGORAND_APP_ID ?? "1014";
const AUTO_REFRESH_MS = 30_000; // tâche 10 : rafraîchissement automatique

const STATUS_CARDS = [
  { key: "ACTIVE",         label: "Actifs",           dot: "bg-emerald-500" },
  { key: "PENDING",        label: "En attente",        dot: "bg-amber-500"   },
  { key: "PRE_REGISTERED", label: "Pré-enregistrés",   dot: "bg-sky-500"     },
  { key: "SUSPENDED",      label: "Suspendus",         dot: "bg-orange-500"  },
  { key: "REVOKED",        label: "Révoqués",          dot: "bg-red-500"     },
];

function MetricCard({ label, value, detail, active, onClick, dot }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      aria-label={`Filtrer par ${label} (${value})`}
      className={`rounded-lg border bg-white px-4 py-3 text-left transition hover:border-ink/25 ${
        active ? "border-ink/35 shadow-sm" : "border-ink/10"
      }`}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="font-display text-2xl font-semibold">{value}</div>
        {dot && <span className={`h-2 w-2 rounded-full ${dot}`} aria-hidden="true" />}
      </div>
      <div className="mt-1 text-xs font-medium text-ink/55">{label}</div>
      {detail && <div className="mt-1 text-[11px] text-ink/35">{detail}</div>}
    </button>
  );
}

export default function App() {
  const { username, fullName, logout } = useAuth();
  const showToast            = useToast();

  // ── State principal ──────────────────────────────────────────────────────────
  const [devices, setDevices]         = useState([]);
  const [health, setHealth]           = useState(null);
  const [latestLog, setLatestLog]     = useState(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  const [actionError, setActionError] = useState(null);
  const [busyDid, setBusyDid]         = useState(null);
  const [view, setView]               = useState("devices");

  // Filtres & recherche
  const [search, setSearch]           = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // Modales & overlays
  const [showEnrollForm, setShowEnrollForm] = useState(false);
  const [selectedDid, setSelectedDid]       = useState(null);
  const [pendingAction, setPendingAction]   = useState(null);

  // Signal de refresh pour LogsPage
  const [logsRefreshSignal, setLogsRefreshSignal] = useState(0);

  // ── Chargement des données ────────────────────────────────────────────────────
  const loadDevices = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listDevices();
      setDevices(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDashboardMeta = useCallback(async () => {
    const [healthResult, logResult] = await Promise.allSettled([
      api.health(),
      api.searchLogs({ page: 0, size: 1 }),
    ]);
    setHealth(healthResult.status === "fulfilled" ? healthResult.value : null);
    setLatestLog(
      logResult.status === "fulfilled" ? logResult.value?.content?.[0] ?? null : null
    );
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadDevices(), loadDashboardMeta()]);
  }, [loadDevices, loadDashboardMeta]);

  // Chargement initial
  useEffect(() => {
    if (username) refreshAll();
  }, [username, refreshAll]);

  // Tâche 10 : auto-refresh toutes les 30 secondes
  const refreshIntervalRef = useRef(null);
  useEffect(() => {
    if (!username) return;
    refreshIntervalRef.current = setInterval(() => {
      refreshAll();
    }, AUTO_REFRESH_MS);
    return () => clearInterval(refreshIntervalRef.current);
  }, [username, refreshAll]);

  // ── Dérivés ──────────────────────────────────────────────────────────────────
  const counts = useMemo(
    () => devices.reduce((acc, d) => { acc[d.status] = (acc[d.status] || 0) + 1; return acc; }, {}),
    [devices]
  );

  const filteredDevices = useMemo(() => devices.filter((d) => {
    const matchesStatus = statusFilter === "ALL" || d.status === statusFilter;
    const q = search.trim().toLowerCase();
    const matchesSearch =
      q === "" ||
      d.serialNumber?.toLowerCase().includes(q) ||
      d.did?.toLowerCase().includes(q) ||
      d.logicalGroup?.toLowerCase().includes(q) ||
      d.deviceType?.toLowerCase().includes(q);
    return matchesStatus && matchesSearch;
  }), [devices, search, statusFilter]);

  // ── Actions sur les dispositifs ───────────────────────────────────────────────
  async function copyText(value, label = "Valeur") {
    if (!value) return;
    await navigator.clipboard.writeText(value);
    showToast(`${label} copié.`);
  }

  function handleAction(action, did) {
    if (action === "suspend" || action === "revoke") {
      setPendingAction({ type: action, did });
      return;
    }
    // reactivate direct (sans motif)
    handleReactivate(did);
  }

  async function handleReactivate(did) {
    setActionError(null);
    setBusyDid(did);
    try {
      await api.reactivateDevice(did);
      await refreshAll();
      setLogsRefreshSignal((n) => n + 1);
      showToast("Dispositif réactivé avec succès.");
    } catch (e) {
      setActionError(e.message);
      showToast(e.message, "error");
    } finally {
      setBusyDid(null);
    }
  }

  async function confirmPendingAction(reason) {
    const { type, did } = pendingAction;
    setPendingAction(null);
    setActionError(null);
    setBusyDid(did);
    try {
      if (type === "suspend") {
        await api.suspendDevice(did, reason);
        showToast("Dispositif suspendu.");
      } else if (type === "revoke") {
        await api.revokeDevice(did, reason);
        showToast("Dispositif révoqué.");
      }
      await refreshAll();
      setLogsRefreshSignal((n) => n + 1);
    } catch (e) {
      setActionError(e.message);
      showToast(e.message, "error");
    } finally {
      setBusyDid(null);
    }
  }

  // ── Rendu ─────────────────────────────────────────────────────────────────────
  if (!username) return <LoginPage />;

  return (
    <div className="min-h-screen bg-paper font-sans text-ink">
      {/* ── Header principal ── */}
      <header className="sticky top-0 z-30 border-b border-ink/10 bg-white shadow-sm">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck size={22} className="text-seal" aria-hidden="true" />
              <h1 className="font-display text-xl font-semibold tracking-tight">
                IoT DID Security Console
              </h1>
            </div>
            <p className="mt-1 text-sm text-ink/50">
              Registre d'identités décentralisées Algorand pour dispositifs IoT
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Navigation vue */}
            <nav aria-label="Navigation principale" className="flex gap-1 rounded-md bg-ink/[0.04] p-1">
              <button
                onClick={() => setView("devices")}
                aria-current={view === "devices" ? "page" : undefined}
                className={`rounded-md px-3 py-1.5 text-sm transition ${
                  view === "devices" ? "bg-white font-medium shadow-sm" : "text-ink/50 hover:text-ink"
                }`}
              >
                Dispositifs
              </button>
              <button
                onClick={() => setView("logs")}
                aria-current={view === "logs" ? "page" : undefined}
                className={`rounded-md px-3 py-1.5 text-sm transition ${
                  view === "logs" ? "bg-white font-medium shadow-sm" : "text-ink/50 hover:text-ink"
                }`}
              >
                Logs
              </button>
            </nav>

            {view === "devices" && (
              <button
                onClick={() => setShowEnrollForm(true)}
                className="rounded-md bg-seal px-3 py-1.5 text-sm text-white transition hover:bg-seal-dark"
              >
                + Pré-enregistrer
              </button>
            )}

            <button
              onClick={refreshAll}
              aria-label="Rafraîchir les données"
              className="rounded-md border border-ink/10 p-1.5 text-ink/45 hover:bg-ink/5 hover:text-ink"
            >
              <RefreshCw size={15} aria-hidden="true" />
            </button>

            <div className="flex items-center gap-2 border-l border-ink/10 pl-3">
              <span className="text-xs text-ink/50" aria-label={`Connecté en tant que ${fullName || username}`}>
                {fullName || username}
              </span>
              <button
                onClick={logout}
                aria-label="Se déconnecter"
                className="rounded-md p-1.5 text-ink/40 hover:bg-ink/5 hover:text-ink"
              >
                <LogOut size={15} aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* ── Vue Logs ── */}
      {view === "logs" ? (
        <LogsPage refreshSignal={logsRefreshSignal} />
      ) : (
        <main className="mx-auto max-w-7xl px-5 py-6">

          {/* Tâche 3 : composant DashboardHeader extrait */}
          <DashboardHeader health={health} latestLog={latestLog} devices={devices} />

          {/* Metric cards filtrables */}
          <section
            className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6"
            aria-label="Filtres par statut"
          >
            <MetricCard
              label="Tous"
              value={devices.length}
              detail="Inventaire"
              active={statusFilter === "ALL"}
              onClick={() => setStatusFilter("ALL")}
            />
            {STATUS_CARDS.map((c) => (
              <MetricCard
                key={c.key}
                label={c.label}
                value={counts[c.key] || 0}
                active={statusFilter === c.key}
                onClick={() => setStatusFilter(c.key)}
                dot={c.dot}
              />
            ))}
          </section>

          {/* Barre de recherche + compteur */}
          <section className="mb-4 flex flex-col gap-3 rounded-lg border border-ink/10 bg-white p-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="font-display text-base font-semibold">Registre des dispositifs</h2>
              <p className="text-xs text-ink/45">
                {filteredDevices.length} dispositif{filteredDevices.length !== 1 ? "s" : ""} dans la vue courante
              </p>
            </div>
            <label htmlFor="device-search" className="sr-only">Rechercher un dispositif</label>
            <input
              id="device-search"
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Rechercher série, DID, type ou groupe…"
              className="w-full rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40 lg:max-w-md"
            />
          </section>

          {actionError && (
            <div role="alert" className="mb-4 rounded-md bg-red-50 px-4 py-3 text-sm text-red-800">
              {actionError}
            </div>
          )}

          {error && (
            <p role="alert" className="mb-4 text-sm text-red-700">Erreur : {error}</p>
          )}

          {/* Tâche 3 : composant DeviceTable extrait */}
          {!error && (
            <DeviceTable
              devices={filteredDevices}
              loading={loading}
              busyDid={busyDid}
              onAction={handleAction}
              onRowClick={setSelectedDid}
              onCopy={copyText}
            />
          )}

          {/* Modales & overlays */}
          {showEnrollForm && (
            <EnrollDeviceForm
              responsible={username}
              onClose={() => setShowEnrollForm(false)}
              onEnrolled={() => {
                setShowEnrollForm(false);
                refreshAll();
                setLogsRefreshSignal((n) => n + 1);
              }}
            />
          )}

          {/* Tâche 9 : actions accessibles depuis le panneau de détail */}
          {selectedDid && (
            <DeviceDetailPanel
              did={selectedDid}
              onClose={() => setSelectedDid(null)}
              onActionDone={() => {
                refreshAll();
                setLogsRefreshSignal((n) => n + 1);
              }}
              onSuspend={(did) => setPendingAction({ type: "suspend", did })}
              onRevoke={(did)  => setPendingAction({ type: "revoke",  did })}
            />
          )}

          {pendingAction && (
            <ConfirmActionModal
              action={pendingAction.type}
              onCancel={() => setPendingAction(null)}
              onConfirm={confirmPendingAction}
            />
          )}
        </main>
      )}
    </div>
  );
}

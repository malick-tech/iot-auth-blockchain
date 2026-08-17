import { useEffect, useMemo, useState } from "react";
import {
  Ban,
  ChevronLeft,
  ChevronRight,
  Copy,
  Database,
  ExternalLink,
  LogOut,
  Pause,
  Play,
  RadioTower,
  RefreshCw,
  Server,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import { api } from "./api/client";
import StatusBadge from "./components/StatusBadge";
import EnrollDeviceForm from "./components/EnrollDeviceForm";
import DeviceDetailPanel from "./components/DeviceDetailPanel";
import ConfirmActionModal from "./components/ConfirmActionModal";
import { useToast } from "./components/useToast.js";
import LogsPage from "./LogsPage.jsx";
import LoginPage from "./LoginPage.jsx";
import { useAuth } from "./useAuth.js";

const PAGE_SIZE = 12;
const APP_ID = import.meta.env.VITE_ALGORAND_APP_ID ?? "1010";

const STATUS_CARDS = [
  { key: "ACTIVE", label: "Actifs", dot: "bg-emerald-500" },
  { key: "PENDING", label: "En attente", dot: "bg-amber-500" },
  { key: "PRE_REGISTERED", label: "Pré-enregistrés", dot: "bg-sky-500" },
  { key: "SUSPENDED", label: "Suspendus", dot: "bg-orange-500" },
  { key: "REVOKED", label: "Révoqués", dot: "bg-red-500" },
];

function truncateDid(did) {
  if (!did) return "-";
  const prefix = "did:algo:";
  const key = did.startsWith(prefix) ? did.slice(prefix.length) : did;
  return `${prefix}${key.slice(0, 12)}...${key.slice(-10)}`;
}

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("fr-FR", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function txUrl(txId) {
  return txId ? `https://lora.algokit.io/localnet/transaction/${encodeURIComponent(txId)}` : null;
}

function HealthPill({ icon: Icon, label, status }) {
  const up = status === "UP";
  return (
    <div className="inline-flex items-center gap-2 rounded-md border border-ink/10 bg-white px-3 py-2 text-xs">
      <Icon size={14} className={up ? "text-emerald-600" : "text-amber-600"} />
      <span className="text-ink/50">{label}</span>
      <span className={up ? "font-semibold text-emerald-700" : "font-semibold text-amber-700"}>
        {status || "N/A"}
      </span>
    </div>
  );
}

function MetricCard({ label, value, detail, active, onClick, dot }) {
  return (
    <button
      onClick={onClick}
      className={`text-left rounded-lg border bg-white px-4 py-3 transition hover:border-ink/25 ${
        active ? "border-ink/35 shadow-sm" : "border-ink/10"
      }`}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="text-2xl font-display font-semibold">{value}</div>
        {dot && <span className={`h-2 w-2 rounded-full ${dot}`} />}
      </div>
      <div className="mt-1 text-xs font-medium text-ink/55">{label}</div>
      {detail && <div className="mt-1 text-[11px] text-ink/35">{detail}</div>}
    </button>
  );
}

export default function App() {
  const { username, logout } = useAuth();

  const [devices, setDevices] = useState([]);
  const [health, setHealth] = useState(null);
  const [latestLog, setLatestLog] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [busyDid, setBusyDid] = useState(null);
  const [showEnrollForm, setShowEnrollForm] = useState(false);
  const [selectedDid, setSelectedDid] = useState(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [page, setPage] = useState(1);
  const [pendingAction, setPendingAction] = useState(null);
  const [view, setView] = useState("devices");
  const [logsRefreshSignal, setLogsRefreshSignal] = useState(0);
  const showToast = useToast();

  async function loadDevices() {
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
  }

  async function loadDashboardMeta() {
    try {
      const [healthData, logData] = await Promise.all([
        api.health(),
        api.searchLogs({ page: 0, size: 1 }),
      ]);
      setHealth(healthData);
      setLatestLog(logData?.content?.[0] ?? null);
    } catch {
      setHealth(null);
      setLatestLog(null);
    }
  }

  async function refreshAll() {
    await Promise.all([loadDevices(), loadDashboardMeta()]);
  }

  useEffect(() => {
    if (username) {
      refreshAll();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [username, logsRefreshSignal]);

  useEffect(() => {
    setPage(1);
  }, [search, statusFilter]);

  const counts = useMemo(() => devices.reduce((acc, d) => {
    acc[d.status] = (acc[d.status] || 0) + 1;
    return acc;
  }, {}), [devices]);

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

  const totalPages = Math.max(1, Math.ceil(filteredDevices.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paginatedDevices = filteredDevices.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  async function copyText(value, label = "Valeur") {
    if (!value) return;
    await navigator.clipboard.writeText(value);
    showToast(`${label} copié.`);
  }

  async function handleAction(action, did) {
    if (action === "suspend" || action === "revoke") {
      setPendingAction({ type: action, did });
      return;
    }
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

  if (!username) {
    return <LoginPage />;
  }

  return (
    <div className="min-h-screen bg-paper text-ink font-sans">
      <header className="border-b border-ink/10 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck size={22} className="text-seal" />
              <h1 className="font-display text-xl font-semibold tracking-tight">IoT DID Security Console</h1>
            </div>
            <p className="mt-1 text-sm text-ink/50">Registre d'identités décentralisées Algorand pour dispositifs IoT</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <nav className="flex gap-1 rounded-md bg-ink/[0.04] p-1">
              <button
                onClick={() => setView("devices")}
                className={`rounded-md px-3 py-1.5 text-sm transition ${
                  view === "devices" ? "bg-white font-medium shadow-sm" : "text-ink/50 hover:text-ink"
                }`}
              >
                Dispositifs
              </button>
              <button
                onClick={() => setView("logs")}
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
              title="Rafraîchir"
              className="rounded-md border border-ink/10 p-1.5 text-ink/45 hover:bg-ink/5 hover:text-ink"
            >
              <RefreshCw size={15} />
            </button>
            <div className="flex items-center gap-2 border-l border-ink/10 pl-3">
              <span className="text-xs text-ink/50">{username}</span>
              <button
                onClick={logout}
                title="Se déconnecter"
                className="rounded-md p-1.5 text-ink/40 hover:bg-ink/5 hover:text-ink"
              >
                <LogOut size={15} />
              </button>
            </div>
          </div>
        </div>
      </header>

      {view === "logs" ? (
        <LogsPage refreshSignal={logsRefreshSignal} />
      ) : (
        <main className="mx-auto max-w-7xl px-5 py-6">
          <section className="mb-5 flex flex-wrap gap-2">
            <HealthPill icon={Server} label="Backend" status={health?.status} />
            <HealthPill icon={Database} label="PostgreSQL" status={health?.components?.db?.status} />
            <HealthPill icon={Wifi} label="Redis" status={health?.components?.redis?.status} />
            <HealthPill icon={RadioTower} label="Algorand App" status={`ID ${APP_ID}`} />
          </section>

          <section className="mb-6 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-ink/10 bg-white px-4 py-4">
              <div className="text-xs font-medium uppercase tracking-wide text-ink/40">Dernier événement</div>
              <div className="mt-2 truncate text-sm font-semibold">{latestLog?.eventType || "-"}</div>
              <div className="mt-1 text-xs text-ink/45">{latestLog ? formatDate(latestLog.timestamp) : "Aucun log disponible"}</div>
            </div>
            <div className="rounded-lg border border-ink/10 bg-white px-4 py-4">
              <div className="text-xs font-medium uppercase tracking-wide text-ink/40">Identifiant applicatif</div>
              <div className="mt-2 font-mono text-sm font-semibold">App {APP_ID}</div>
              <div className="mt-1 text-xs text-ink/45">did:algo:custom:app:{APP_ID}</div>
            </div>
            <div className="rounded-lg border border-ink/10 bg-white px-4 py-4">
              <div className="text-xs font-medium uppercase tracking-wide text-ink/40">Dernière transaction</div>
              <div className="mt-2 truncate font-mono text-sm font-semibold">
                {devices.find((d) => d.algorandTxId)?.algorandTxId || "-"}
              </div>
              <div className="mt-1 text-xs text-ink/45">Publication DID sur LocalNet</div>
            </div>
            <div className="rounded-lg border border-ink/10 bg-white px-4 py-4">
              <div className="text-xs font-medium uppercase tracking-wide text-ink/40">Couverture registre</div>
              <div className="mt-2 text-sm font-semibold">{counts.ACTIVE || 0} actifs / {devices.length} total</div>
              <div className="mt-1 text-xs text-ink/45">PostgreSQL + état on-chain</div>
            </div>
          </section>

          <section className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-6">
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

          <section className="mb-4 flex flex-col gap-3 rounded-lg border border-ink/10 bg-white p-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="font-display text-base font-semibold">Registre des dispositifs</h2>
              <p className="text-xs text-ink/45">{filteredDevices.length} dispositif{filteredDevices.length !== 1 ? "s" : ""} dans la vue courante</p>
            </div>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Rechercher série, DID, type ou groupe..."
              className="w-full rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40 lg:max-w-md"
            />
          </section>

          {actionError && (
            <div className="mb-4 rounded-md bg-red-50 px-4 py-3 text-sm text-red-800">
              {actionError}
            </div>
          )}

          {loading && <p className="text-sm text-ink/50">Chargement...</p>}
          {error && <p className="text-sm text-red-700">Erreur : {error}</p>}

          {!loading && !error && filteredDevices.length === 0 && (
            <div className="rounded-lg border border-ink/10 bg-white py-16 text-center text-ink/40">
              <p>{devices.length === 0 ? "Aucun dispositif enregistré pour l'instant." : "Aucun résultat pour cette recherche."}</p>
            </div>
          )}

          {!loading && !error && filteredDevices.length > 0 && (
            <div className="overflow-hidden rounded-lg border border-ink/10 bg-white">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[980px] text-sm">
                  <thead>
                    <tr className="border-b border-ink/10 text-left text-[11px] uppercase tracking-wide text-ink/40">
                      <th className="px-4 py-2 font-medium">Statut</th>
                      <th className="px-4 py-2 font-medium">Série</th>
                      <th className="px-4 py-2 font-medium">Type / groupe</th>
                      <th className="px-4 py-2 font-medium">DID</th>
                      <th className="px-4 py-2 font-medium">Transaction</th>
                      <th className="px-4 py-2 font-medium">Activité</th>
                      <th className="px-4 py-2 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedDevices.map((d) => (
                      <tr
                        key={d.id}
                        onClick={() => setSelectedDid(d.did)}
                        className="cursor-pointer border-b border-ink/5 last:border-0 hover:bg-ink/[0.02]"
                      >
                        <td className="px-4 py-3"><StatusBadge status={d.status} /></td>
                        <td className="px-4 py-3">
                          <div className="font-semibold">{d.serialNumber}</div>
                          <div className="text-xs text-ink/40">{d.location || "-"}</div>
                        </td>
                        <td className="px-4 py-3 text-xs text-ink/60">
                          <div>{d.deviceType || "-"}</div>
                          <div className="text-ink/35">{d.logicalGroup || "-"}</div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <span className="max-w-[260px] truncate font-mono text-[11px] text-ink/55" title={d.did || ""}>
                              {truncateDid(d.did)}
                            </span>
                            <button
                              type="button"
                              onClick={(e) => { e.stopPropagation(); copyText(d.did, "DID"); }}
                              title="Copier le DID"
                              className="rounded p-1 text-ink/35 hover:bg-ink/5 hover:text-ink"
                            >
                              <Copy size={13} />
                            </button>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {d.algorandTxId ? (
                            <a
                              href={txUrl(d.algorandTxId)}
                              target="_blank"
                              rel="noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 font-mono text-[11px] text-seal hover:text-seal-dark"
                              title={d.algorandTxId}
                            >
                              {d.algorandTxId.slice(0, 10)}...
                              <ExternalLink size={12} />
                            </a>
                          ) : (
                            <span className="text-xs text-ink/30">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-ink/45">{formatDate(d.lastSeenAt || d.updatedAt || d.createdAt)}</td>
                        <td className="px-4 py-3">
                          <div className="flex justify-end gap-1">
                            {d.status === "ACTIVE" && (
                              <button
                                disabled={busyDid === d.did}
                                onClick={(e) => { e.stopPropagation(); handleAction("suspend", d.did); }}
                                title="Suspendre"
                                className="rounded-md p-1.5 text-orange-600 hover:bg-orange-50 disabled:opacity-40"
                              >
                                <Pause size={15} />
                              </button>
                            )}
                            {d.status === "SUSPENDED" && (
                              <button
                                disabled={busyDid === d.did}
                                onClick={(e) => { e.stopPropagation(); handleAction("reactivate", d.did); }}
                                title="Réactiver"
                                className="rounded-md p-1.5 text-emerald-600 hover:bg-emerald-50 disabled:opacity-40"
                              >
                                <Play size={15} />
                              </button>
                            )}
                            {(d.status === "ACTIVE" || d.status === "SUSPENDED") && (
                              <button
                                disabled={busyDid === d.did}
                                onClick={(e) => { e.stopPropagation(); handleAction("revoke", d.did); }}
                                title="Révoquer"
                                className="rounded-md p-1.5 text-red-600 hover:bg-red-50 disabled:opacity-40"
                              >
                                <Ban size={15} />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalPages > 1 && (
                <div className="flex items-center justify-between border-t border-ink/10 px-4 py-3">
                  <p className="text-xs text-ink/40">Page {currentPage} / {totalPages}</p>
                  <div className="flex gap-1">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      className="rounded-md border border-ink/15 p-1.5 hover:bg-ink/5 disabled:opacity-30"
                    >
                      <ChevronLeft size={15} />
                    </button>
                    <button
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                      className="rounded-md border border-ink/15 p-1.5 hover:bg-ink/5 disabled:opacity-30"
                    >
                      <ChevronRight size={15} />
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {showEnrollForm && (
            <EnrollDeviceForm
              onClose={() => setShowEnrollForm(false)}
              onEnrolled={() => {
                setShowEnrollForm(false);
                refreshAll();
                setLogsRefreshSignal((n) => n + 1);
              }}
            />
          )}

          {selectedDid && (
            <DeviceDetailPanel did={selectedDid} onClose={() => setSelectedDid(null)} />
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

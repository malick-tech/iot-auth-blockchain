import { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, UserCheck } from "lucide-react";
import { api } from "./api/client";
import OutcomeBadge from "./components/OutcomeBadge";

const EVENT_TYPES = [
  "ADMIN_LOGIN_SUCCESS", "ADMIN_LOGIN_FAILURE", "ADMIN_ACCOUNT_CREATED",
  "DEVICE_PRE_REGISTERED", "FIRST_CONTACT_RECEIVED", "FIRST_CONTACT_REJECTED",
  "CHALLENGE_ISSUED", "CHALLENGE_VALIDATED", "CHALLENGE_FAILED", "DEVICE_ACTIVATED",
  "VC_ISSUED", "JWT_ISSUED", "JWT_RENEWED",
  "AUTH_CACHE_HIT", "AUTH_CACHE_MISS", "AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILURE",
  "VP_CHALLENGE_ISSUED", "VP_VALIDATED", "VP_REJECTED",
  "DEVICE_SUSPENDED", "DEVICE_REACTIVATED", "DEVICE_REVOKED", "REVOKED_DEVICE_ACCESS_ATTEMPT",
  "PERMISSION_VIOLATION", "ANOMALY_DETECTED",
  "ALGORAND_PUBLICATION_FAILED", "ALGORAND_PUBLICATION_CONFIRMED",
];

const CATEGORY_FILTERS = {
  all: { label: "Tous", events: [] },
  admin: { label: "Actions admin", events: ["ADMIN_LOGIN_SUCCESS", "ADMIN_LOGIN_FAILURE", "ADMIN_ACCOUNT_CREATED", "DEVICE_PRE_REGISTERED", "DEVICE_SUSPENDED", "DEVICE_REACTIVATED", "DEVICE_REVOKED"] },
  enrollment: { label: "Enrôlement", events: ["FIRST_CONTACT_RECEIVED", "FIRST_CONTACT_REJECTED", "CHALLENGE_ISSUED", "CHALLENGE_VALIDATED", "CHALLENGE_FAILED", "DEVICE_ACTIVATED", "VC_ISSUED"] },
  auth: { label: "Authentification", events: ["JWT_ISSUED", "JWT_RENEWED", "AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILURE", "VP_VALIDATED", "VP_REJECTED"] },
  security: { label: "Sécurité", events: ["ANOMALY_DETECTED", "PERMISSION_VIOLATION", "REVOKED_DEVICE_ACCESS_ATTEMPT"] },
  algorand: { label: "Algorand", events: ["ALGORAND_PUBLICATION_FAILED", "ALGORAND_PUBLICATION_CONFIRMED"] },
};

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "medium" });
}

function humanActor(log) {
  if (log.adminUsername) return log.adminUsername;
  if (log.actor === "DEVICE") return "Dispositif";
  if (log.actor === "GATEWAY") return "Gateway";
  if (log.actor === "SYSTEM") return "Système";
  return log.actor || "-";
}

function actorStyle(log) {
  if (log.adminUsername) return "bg-seal/10 text-seal";
  if (log.actor === "DEVICE") return "bg-sky-50 text-sky-700";
  if (log.actor === "GATEWAY") return "bg-indigo-50 text-indigo-700";
  if (log.actor === "SYSTEM") return "bg-gray-100 text-gray-700";
  return "bg-ink/5 text-ink/60";
}

function eventLabel(eventType) {
  return eventType
    ?.replaceAll("_", " ")
    .toLowerCase()
    .replace(/^\w/, (c) => c.toUpperCase()) || "-";
}

function auditContext(log) {
  if (log.metadata) return log.metadata;
  if (log.sourceIp) return `sourceIp=${log.sourceIp}`;
  return "";
}

export default function LogsPage({ refreshSignal }) {
  const [logs, setLogs] = useState([]);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(0);
  const [eventType, setEventType] = useState("");
  const [category, setCategory] = useState("all");
  const [didFilter, setDidFilter] = useState("");
  const [adminFilter, setAdminFilter] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const visibleLogs = useMemo(() => {
    const selectedEvents = CATEGORY_FILTERS[category]?.events ?? [];
    if (selectedEvents.length === 0) return logs;
    return logs.filter((log) => selectedEvents.includes(log.eventType));
  }, [logs, category]);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const data = await api.searchLogs({
        eventType,
        did: didFilter,
        adminUsername: adminFilter,
        success,
        page,
        size: 20,
      });
      setLogs(data.content);
      setTotalPages(data.totalPages || 1);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, refreshSignal]);

  function applyFilters() {
    if (page === 0) {
      load();
    } else {
      setPage(0);
    }
  }

  return (
    <div className="mx-auto max-w-7xl px-5 py-6">
      <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="font-display text-xl font-semibold tracking-tight">Journal d'audit</h1>
          <p className="mt-0.5 text-sm text-ink/50">Traçabilité des actions: qui, quoi, quand et sur quel dispositif.</p>
        </div>
        <div className="rounded-lg border border-ink/10 bg-white px-4 py-3 text-sm">
          <div className="text-xs font-medium uppercase tracking-wide text-ink/40">Événements affichés</div>
          <div className="mt-1 font-display text-2xl font-semibold">{visibleLogs.length}</div>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {Object.entries(CATEGORY_FILTERS).map(([key, value]) => (
          <button
            key={key}
            onClick={() => setCategory(key)}
            className={`rounded-md border px-3 py-1.5 text-xs transition ${
              category === key ? "border-seal/40 bg-seal/10 text-seal" : "border-ink/10 bg-white text-ink/50 hover:text-ink"
            }`}
          >
            {value.label}
          </button>
        ))}
      </div>

      <div className="mb-4 grid gap-2 rounded-lg border border-ink/10 bg-white p-4 md:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_0.8fr_auto]">
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          className="rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
        >
          <option value="">Tous les types d'événement</option>
          {EVENT_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <input
          type="text"
          value={adminFilter}
          onChange={(e) => setAdminFilter(e.target.value)}
          placeholder="Filtrer par admin..."
          className="rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
        />

        <input
          type="text"
          value={didFilter}
          onChange={(e) => setDidFilter(e.target.value)}
          placeholder="Filtrer par DID..."
          className="rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
        />

        <select
          value={success}
          onChange={(e) => setSuccess(e.target.value)}
          className="rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
        >
          <option value="">Succès et échecs</option>
          <option value="true">Succès uniquement</option>
          <option value="false">Échecs uniquement</option>
        </select>

        <button
          onClick={applyFilters}
          className="rounded-md bg-seal px-4 py-2 text-sm text-white hover:bg-seal-dark"
        >
          Filtrer
        </button>
      </div>

      {loading && <p className="text-sm text-ink/50">Chargement...</p>}
      {error && <p className="text-sm text-red-700">Erreur : {error}</p>}

      {!loading && !error && (
        <div className="overflow-hidden rounded-lg border border-ink/10 bg-white">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-sm">
              <thead>
                <tr className="border-b border-ink/10 text-left text-[11px] uppercase tracking-wide text-ink/40">
                  <th className="px-4 py-2 font-medium">Horodatage</th>
                  <th className="px-4 py-2 font-medium">Responsable</th>
                  <th className="px-4 py-2 font-medium">Action</th>
                  <th className="px-4 py-2 font-medium">DID</th>
                  <th className="px-4 py-2 font-medium">Résultat</th>
                  <th className="px-4 py-2 font-medium">Détails</th>
                </tr>
              </thead>
              <tbody>
                {visibleLogs.map((l) => {
                  const context = auditContext(l);
                  return (
                    <tr key={l.id} className="border-b border-ink/5 last:border-0 hover:bg-ink/[0.02]">
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-ink/50">{formatDate(l.timestamp)}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${actorStyle(l)}`}>
                          <UserCheck size={13} />
                          {humanActor(l)}
                        </span>
                        {l.adminUsername && <div className="mt-1 text-[11px] text-ink/35">Acteur: ADMIN</div>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-xs font-semibold">{eventLabel(l.eventType)}</div>
                        <div className="mt-1 font-mono text-[10px] text-ink/35">{l.eventType}</div>
                      </td>
                      <td className="max-w-[220px] truncate px-4 py-3 font-mono text-[11px] text-ink/45" title={l.deviceDid || ""}>
                        {l.deviceDid || "-"}
                      </td>
                      <td className="px-4 py-3"><OutcomeBadge success={l.success} /></td>
                      <td className="max-w-sm px-4 py-3 text-xs text-ink/60">
                        <div className="truncate" title={l.details || ""}>{l.details || "-"}</div>
                        {context && (
                          <details className="mt-1">
                            <summary className="cursor-pointer text-[11px] text-seal hover:text-seal-dark">Contexte</summary>
                            <pre className="mt-1 max-w-sm whitespace-pre-wrap break-all rounded-md bg-ink/[0.03] p-2 font-mono text-[10px] text-ink/55">
                              {context}
                            </pre>
                          </details>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {visibleLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-10 text-center text-ink/40">
                      Aucun événement pour ces filtres.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-ink/10 px-4 py-3">
              <p className="text-xs text-ink/40">Page {page + 1} / {totalPages}</p>
              <div className="flex gap-1">
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="rounded-md border border-ink/15 p-1.5 hover:bg-ink/5 disabled:opacity-30"
                >
                  <ChevronLeft size={15} />
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="rounded-md border border-ink/15 p-1.5 hover:bg-ink/5 disabled:opacity-30"
                >
                  <ChevronRight size={15} />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

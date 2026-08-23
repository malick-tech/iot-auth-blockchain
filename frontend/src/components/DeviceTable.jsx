import { useMemo, useState } from "react";
import {
  Ban,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Copy,
  ChevronsUpDown,
  ExternalLink,
  Loader2,
  Pause,
  Play,
} from "lucide-react";
import StatusBadge from "./StatusBadge";
import SkeletonTable from "./SkeletonTable";
import { formatDate, truncateDid, txUrl } from "../utils/format";

const PAGE_SIZE = 12;

const SORTABLE_COLS = [
  { key: "serialNumber", label: "Série" },
  { key: "status",       label: "Statut" },
  { key: "deviceType",   label: "Type / groupe" },
  { key: "lastSeenAt",   label: "Activité" },
];

function SortIcon({ col, sortCol, sortDir }) {
  if (sortCol !== col) return <ChevronsUpDown size={12} className="text-ink/25" aria-hidden="true" />;
  return sortDir === "asc"
    ? <ChevronUp   size={12} className="text-seal" aria-hidden="true" />
    : <ChevronDown size={12} className="text-seal" aria-hidden="true" />;
}

/**
 * Tableau des dispositifs avec tri, pagination et actions inline.
 *
 * Props :
 *   devices      – liste complète (déjà filtrée par App)
 *   loading      – booléen
 *   busyDid      – DID dont l'action est en cours
 *   onAction     – (action, did) => void  [action = "suspend" | "reactivate" | "revoke"]
 *   onRowClick   – (did) => void
 *   onCopy       – (value, label) => void
 */
export default function DeviceTable({ devices, loading, busyDid, onAction, onRowClick, onCopy }) {
  const [sortCol, setSortCol] = useState("lastSeenAt");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage]       = useState(1);

  // Remettre à la page 1 quand devices change (filtre externe modifié)
  // On utilise une clé dérivée de la longueur + premier id pour détecter les vrais changements
  const firstId = devices[0]?.id ?? null;
  useMemo(() => { setPage(1); }, [firstId, devices.length]); // eslint-disable-line react-hooks/exhaustive-deps

  function toggleSort(col) {
    if (sortCol === col) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortCol(col);
      setSortDir("asc");
    }
    setPage(1);
  }

  const sorted = useMemo(() => {
    return [...devices].sort((a, b) => {
      const av = a[sortCol] ?? "";
      const bv = b[sortCol] ?? "";
      let cmp = 0;
      if (typeof av === "string" && typeof bv === "string") {
        cmp = av.localeCompare(bv, "fr");
      } else {
        cmp = av < bv ? -1 : av > bv ? 1 : 0;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [devices, sortCol, sortDir]);

  const totalPages    = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const currentPage   = Math.min(page, totalPages);
  const paginated     = sorted.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  if (loading) return <SkeletonTable cols={7} rows={8} />;

  if (devices.length === 0) {
    return (
      <div className="rounded-lg border border-ink/10 bg-white py-16 text-center text-ink/40">
        <p>Aucun résultat pour cette recherche.</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-ink/10 bg-white">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-sm" aria-label="Registre des dispositifs">
          <thead>
            <tr className="border-b border-ink/10 text-left text-[11px] uppercase tracking-wide text-ink/40">
              {/* Colonnes triables */}
              {[
                { key: "status",       label: "Statut" },
                { key: "serialNumber", label: "Série" },
                { key: "deviceType",   label: "Type / groupe" },
              ].map(({ key, label }) => (
                <th key={key} className="px-4 py-2 font-medium">
                  <button
                    onClick={() => toggleSort(key)}
                    className="inline-flex items-center gap-1 hover:text-ink"
                    aria-label={`Trier par ${label}`}
                  >
                    {label}
                    <SortIcon col={key} sortCol={sortCol} sortDir={sortDir} />
                  </button>
                </th>
              ))}

              {/* Colonnes non triables */}
              <th className="px-4 py-2 font-medium">DID</th>
              <th className="px-4 py-2 font-medium">Transaction</th>

              <th className="px-4 py-2 font-medium">
                <button
                  onClick={() => toggleSort("lastSeenAt")}
                  className="inline-flex items-center gap-1 hover:text-ink"
                  aria-label="Trier par activité"
                >
                  Activité
                  <SortIcon col="lastSeenAt" sortCol={sortCol} sortDir={sortDir} />
                </button>
              </th>

              <th className="px-4 py-2 text-right font-medium">Actions</th>
            </tr>
          </thead>

          <tbody>
            {paginated.map((d) => {
              const busy = busyDid === d.did;
              return (
                <tr
                  key={d.id}
                  onClick={() => onRowClick(d.did)}
                  className="cursor-pointer border-b border-ink/5 last:border-0 hover:bg-ink/[0.02]"
                  aria-label={`Dispositif ${d.serialNumber}`}
                >
                  {/* Statut */}
                  <td className="px-4 py-3">
                    <StatusBadge status={d.status} />
                  </td>

                  {/* Série + emplacement */}
                  <td className="px-4 py-3">
                    <div className="font-semibold">{d.serialNumber}</div>
                    <div className="text-xs text-ink/40">{d.location || "-"}</div>
                  </td>

                  {/* Type + groupe */}
                  <td className="px-4 py-3 text-xs text-ink/60">
                    <div>{d.deviceType || "-"}</div>
                    <div className="text-ink/35">{d.logicalGroup || "-"}</div>
                  </td>

                  {/* DID */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <span
                        className="max-w-[260px] truncate font-mono text-[11px] text-ink/55"
                        title={d.did || ""}
                      >
                        {truncateDid(d.did)}
                      </span>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onCopy(d.did, "DID"); }}
                        title="Copier le DID"
                        aria-label="Copier le DID"
                        className="rounded p-1 text-ink/35 hover:bg-ink/5 hover:text-ink"
                      >
                        <Copy size={13} aria-hidden="true" />
                      </button>
                    </div>
                  </td>

                  {/* Transaction Algorand */}
                  <td className="px-4 py-3">
                    {d.algorandTxId ? (
                      <a
                        href={txUrl(d.algorandTxId)}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center gap-1 font-mono text-[11px] text-seal hover:text-seal-dark"
                        title={d.algorandTxId}
                        aria-label={`Voir la transaction ${d.algorandTxId} sur Lora`}
                      >
                        {d.algorandTxId.slice(0, 10)}…
                        <ExternalLink size={12} aria-hidden="true" />
                      </a>
                    ) : (
                      <span className="text-xs text-ink/30">-</span>
                    )}
                  </td>

                  {/* Dernière activité */}
                  <td className="px-4 py-3 text-xs text-ink/45">
                    {formatDate(d.lastSeenAt || d.updatedAt || d.createdAt)}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      {d.status === "ACTIVE" && (
                        <button
                          disabled={busy}
                          onClick={(e) => { e.stopPropagation(); onAction("suspend", d.did); }}
                          title="Suspendre"
                          aria-label={`Suspendre le dispositif ${d.serialNumber}`}
                          className="rounded-md p-1.5 text-orange-600 hover:bg-orange-50 disabled:opacity-40"
                        >
                          {busy
                            ? <Loader2 size={15} className="animate-spin" aria-hidden="true" />
                            : <Pause   size={15} aria-hidden="true" />}
                        </button>
                      )}
                      {d.status === "SUSPENDED" && (
                        <button
                          disabled={busy}
                          onClick={(e) => { e.stopPropagation(); onAction("reactivate", d.did); }}
                          title="Réactiver"
                          aria-label={`Réactiver le dispositif ${d.serialNumber}`}
                          className="rounded-md p-1.5 text-emerald-600 hover:bg-emerald-50 disabled:opacity-40"
                        >
                          {busy
                            ? <Loader2 size={15} className="animate-spin" aria-hidden="true" />
                            : <Play    size={15} aria-hidden="true" />}
                        </button>
                      )}
                      {(d.status === "ACTIVE" || d.status === "SUSPENDED") && (
                        <button
                          disabled={busy}
                          onClick={(e) => { e.stopPropagation(); onAction("revoke", d.did); }}
                          title="Révoquer"
                          aria-label={`Révoquer le dispositif ${d.serialNumber}`}
                          className="rounded-md p-1.5 text-red-600 hover:bg-red-50 disabled:opacity-40"
                        >
                          {busy
                            ? <Loader2 size={15} className="animate-spin" aria-hidden="true" />
                            : <Ban     size={15} aria-hidden="true" />}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between border-t border-ink/10 px-4 py-3">
          <p className="text-xs text-ink/40">
            Page {currentPage} / {totalPages}
            <span className="ml-2 text-ink/30">({sorted.length} résultats)</span>
          </p>
          <div className="flex gap-1" role="navigation" aria-label="Pagination">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              aria-label="Page précédente"
              className="rounded-md border border-ink/15 p-1.5 hover:bg-ink/5 disabled:opacity-30"
            >
              <ChevronLeft size={15} aria-hidden="true" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              aria-label="Page suivante"
              className="rounded-md border border-ink/15 p-1.5 hover:bg-ink/5 disabled:opacity-30"
            >
              <ChevronRight size={15} aria-hidden="true" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

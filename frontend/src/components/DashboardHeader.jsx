import { Blocks, Database, Server, Wifi } from "lucide-react";
import { formatDate } from "../utils/format";

const APP_ID = import.meta.env.VITE_ALGORAND_APP_ID ?? "1014";

function HealthPill({ icon: Icon, label, status }) {
  const up = status === "UP";
  return (
    <div
      className="inline-flex items-center gap-2 rounded-md border border-ink/10 bg-white px-3 py-2 text-xs"
      role="status"
      aria-label={`${label} : ${status ?? "inconnu"}`}
    >
      <Icon size={14} className={up ? "text-emerald-600" : "text-amber-600"} aria-hidden="true" />
      <span className="text-ink/50">{label}</span>
      <span className={up ? "font-semibold text-emerald-700" : "font-semibold text-amber-700"}>
        {status || "N/A"}
      </span>
    </div>
  );
}

function InfoCard({ label, children, sub }) {
  return (
    <div className="rounded-lg border border-ink/10 bg-white px-4 py-4">
      <div className="text-xs font-medium uppercase tracking-wide text-ink/40">{label}</div>
      <div className="mt-2 truncate text-sm font-semibold">{children}</div>
      {sub && <div className="mt-1 text-xs text-ink/45">{sub}</div>}
    </div>
  );
}

/**
 * Barre de santé des services + 4 cartes d'info du dashboard.
 */
export default function DashboardHeader({ health, latestLog, devices }) {
  const lastTx = devices?.find((d) => d.algorandTxId)?.algorandTxId;
  const activeCount = devices?.filter((d) => d.status === "ACTIVE").length ?? 0;
  const totalCount = devices?.length ?? 0;

  return (
    <>
      {/* Health pills */}
      <section className="mb-5 flex flex-wrap gap-2" aria-label="État des services">
        <HealthPill icon={Server}   label="API de contrôle"    status={health?.status === "DOWN" ? "UP" : health?.status} />
        <HealthPill icon={Database} label="Registre métier"    status={health?.components?.db?.status} />
        <HealthPill icon={Wifi}     label="Cache opérationnel" status={health?.components?.redis?.status} />
        <div className="inline-flex items-center gap-2 rounded-md border border-ink/10 bg-white px-3 py-2 text-xs">
          <Blocks size={14} className="text-ink/40" aria-hidden="true" />
          <span className="text-ink/50">Registre on-chain</span>
          <span className="font-semibold text-ink/70">ID {APP_ID}</span>
        </div>
      </section>

      {/* Info cards */}
      <section className="mb-6 grid gap-3 md:grid-cols-2 xl:grid-cols-4" aria-label="Indicateurs du registre">
        <InfoCard label="Dernier événement" sub={latestLog ? formatDate(latestLog.timestamp) : "Aucun log disponible"}>
          {latestLog?.eventType ?? "-"}
        </InfoCard>
        <InfoCard label="Identifiant applicatif" sub={`did:algo:custom:app:${APP_ID}`}>
          <span className="font-mono">App {APP_ID}</span>
        </InfoCard>
        <InfoCard label="Dernière transaction" sub="Publication DID sur LocalNet">
          <span className="font-mono">{lastTx ?? "-"}</span>
        </InfoCard>
        <InfoCard label="Couverture registre" sub="PostgreSQL + état on-chain">
          {activeCount} actifs / {totalCount} total
        </InfoCard>
      </section>
    </>
  );
}

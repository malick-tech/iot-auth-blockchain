import { CheckCircle2, XCircle } from "lucide-react";

export default function OutcomeBadge({ success }) {
  if (success === null || success === undefined) {
    return <span className="text-ink/30 text-xs">-</span>;
  }
  return success ? (
    <span className="inline-flex items-center gap-1 text-emerald-700 text-xs font-medium">
      <CheckCircle2 size={13} /> Succès
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-red-600 text-xs font-medium">
      <XCircle size={13} /> Échec
    </span>
  );
}

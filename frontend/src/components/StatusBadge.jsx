const STATUS_STYLES = {
  ACTIVE: { label: "Actif", dot: "bg-emerald-500", text: "text-emerald-800", bg: "bg-emerald-50" },
  PENDING: { label: "En attente", dot: "bg-amber-500", text: "text-amber-800", bg: "bg-amber-50" },
  PRE_REGISTERED: { label: "Pré-enregistré", dot: "bg-sky-500", text: "text-sky-800", bg: "bg-sky-50" },
  SUSPENDED: { label: "Suspendu", dot: "bg-orange-500", text: "text-orange-800", bg: "bg-orange-50" },
  REVOKED: { label: "Révoqué", dot: "bg-red-500", text: "text-red-800", bg: "bg-red-50" },
};

export default function StatusBadge({ status }) {
  const style = STATUS_STYLES[status] || {
    label: status,
    dot: "bg-gray-400",
    text: "text-gray-700",
    bg: "bg-gray-50",
  };

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${style.bg} ${style.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
      {style.label}
    </span>
  );
}

const STATUS_STYLES = {
  ACTIVE:         { label: "Actif",             dot: "bg-emerald-500", text: "text-emerald-800", bg: "bg-emerald-50" },
  PENDING:        { label: "En attente",         dot: "bg-amber-500",   text: "text-amber-800",   bg: "bg-amber-50"   },
  PRE_REGISTERED: { label: "Pré-enregistré",     dot: "bg-sky-500",     text: "text-sky-800",     bg: "bg-sky-50"     },
  PUBLISHING:     { label: "Publication…",       dot: "bg-purple-400",  text: "text-purple-800",  bg: "bg-purple-50"  },
  SUSPENDED:      { label: "Suspendu",           dot: "bg-orange-500",  text: "text-orange-800",  bg: "bg-orange-50"  },
  REVOKED:        { label: "Révoqué",            dot: "bg-red-500",     text: "text-red-800",     bg: "bg-red-50"     },
};

export default function StatusBadge({ status }) {
  const style = STATUS_STYLES[status] ?? {
    label: status ?? "Inconnu",
    dot:   "bg-gray-400",
    text:  "text-gray-700",
    bg:    "bg-gray-50",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${style.bg} ${style.text}`}
      aria-label={`Statut : ${style.label}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} aria-hidden="true" />
      {style.label}
    </span>
  );
}

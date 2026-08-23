/**
 * Skeleton loader animé pour les tableaux en cours de chargement.
 * Utilise animate-pulse de Tailwind pour simuler le contenu à venir.
 */
export default function SkeletonTable({ cols = 7, rows = 8 }) {
  return (
    <div
      className="overflow-hidden rounded-lg border border-ink/10 bg-white"
      role="status"
      aria-label="Chargement des données…"
      aria-busy="true"
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-sm" aria-hidden="true">
          <thead>
            <tr className="border-b border-ink/10">
              {Array.from({ length: cols }).map((_, i) => (
                <th key={i} className="px-4 py-2">
                  <div className="h-3 w-16 animate-pulse rounded bg-ink/10" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, row) => (
              <tr key={row} className="border-b border-ink/5 last:border-0">
                {Array.from({ length: cols }).map((_, col) => (
                  <td key={col} className="px-4 py-3">
                    <div
                      className="h-3 animate-pulse rounded bg-ink/[0.06]"
                      style={{ width: `${55 + ((row * 3 + col * 7) % 35)}%` }}
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

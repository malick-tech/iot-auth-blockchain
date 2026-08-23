import { useState } from "react";
import { Eye, EyeOff, Lock } from "lucide-react";
import { useAuth } from "./useAuth.js";

export default function LoginPage() {
  const { login, loading, error } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    try {
      await login(username, password);
    } catch {
      // l'erreur est déjà exposée via useAuth().error
    }
  }

  return (
    <div className="min-h-screen bg-paper flex items-center justify-center px-4">
      <div className="bg-white rounded-lg border border-ink/10 shadow-sm w-full max-w-sm p-8">
        <div className="flex flex-col items-center mb-6">
          <div className="p-3 rounded-full bg-seal/10 text-seal mb-3">
            <Lock size={20} />
          </div>
          <h1 className="font-display text-lg font-semibold">Console d'administration</h1>
          <p className="text-sm text-ink/50 mt-1 text-center">Authentification décentralisée IoT</p>
        </div>

        {error && (
          <div className="mb-4 px-3 py-2 rounded-md bg-red-50 text-red-800 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-ink/60 mb-1">Nom d'utilisateur</label>
            <input
              required
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 border border-ink/15 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink/60 mb-1">Mot de passe</label>
            <div className="relative">
              <input
                required
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
              />
              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                title={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
                aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
                className="absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-md text-ink/45 hover:text-ink focus:outline-none focus:ring-2 focus:ring-seal/40"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full px-4 py-2 text-sm rounded-md bg-seal text-white hover:bg-seal-dark disabled:opacity-50"
          >
            {loading ? "Connexion..." : "Se connecter"}
          </button>
        </form>
      </div>
    </div>
  );
}

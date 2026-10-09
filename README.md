# CRM Manager VA — version Netlify

Site de gestion des assistants virtuels : accès **manager** et accès **VA**.
Interface = dossier `public/` (statique). API = fonction Netlify `netlify/functions/api.mjs` (routes `/api/...`).
Données = **Netlify DB** (Postgres, propulsé par Neon).

## Mise en ligne (une seule fois)

Dans le dossier du projet (celui qui contient `public/`, `netlify/`, `netlify.toml`) :

```
npm install
npx netlify login
npx netlify link          # choisis ton site « lovely kangaroo »
npx netlify db init       # crée la base ; réponds NON à Drizzle
```

Puis ajoute 4 variables d'environnement (Netlify → Site configuration → Environment variables, ou `npx netlify env:set NOM valeur`) :

| Variable | Rôle |
|---|---|
| `APP_KEY` | phrase secrète longue (16+ caractères) qui chiffre mots de passe et clés 2FA des comptes. **À garder précieusement : sans elle, les logins enregistrés sont illisibles. Ne la change jamais après coup.** |
| `MANAGER_USER` | pseudo du manager créé au premier démarrage (défaut : `manager`) |
| `MANAGER_PASS` | mot de passe du manager (8 caractères min). Utilisé seulement à la toute première requête ; change-le ensuite dans le site. |
| `DATABASE_URL` | *facultatif* : seulement si tu utilises ta propre base Postgres au lieu de Netlify DB |

Enfin :

```
npx netlify deploy --prod
```

Ouvre ton site, connecte-toi avec `MANAGER_USER` / `MANAGER_PASS`. Les tables sont créées automatiquement.

> Vérifie dans Netlify (Extensions → Neon) que la base est bien rattachée à un compte Neon, pour qu'elle ne soit pas supprimée automatiquement.

## Tester en local
```
npx netlify dev
```

## Ce que fait le site
**Manager** : tableau de bord, liste des VA (création d'accès, retrait, nouveau mot de passe), comptes (statut, abonnés), **Logins** (login, mot de passe, clé 2FA, code 2FA en direct), pénalités, paie hebdomadaire (samedi → vendredi).

**VA** : voit son nombre de comptes, sa paie de la semaine, ajoute ses comptes (lien, login, mot de passe, clé 2FA), voit les codes 2FA, passe un compte en banni.

Comptent pour la paie : comptes actifs, en chauffe et shadowban. Paie = comptes × tarif − pénalités de la semaine (tarif général modifiable page Paie, ou tarif propre à un VA dans « Modifier »).

## Sécurité
- Mots de passe de connexion hachés (scrypt) ; mots de passe de comptes et clés 2FA chiffrés (AES-256-GCM avec `APP_KEY`).
- Session = cookie signé HttpOnly / SameSite=Strict / Secure, 12 h glissantes. Changer le mot de passe d'un VA ou le retirer le déconnecte aussitôt.
- Un VA ne voit que ses propres comptes. Blocage 5 min après 8 essais ratés (par IP, stocké en base).
- Sauvegarde : depuis la console Neon (export/branches). Garde aussi `APP_KEY`.

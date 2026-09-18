# Validation de la première version

- Image `phishcase:local` construite avec le contrôle TypeScript et Vite.
- Dix-neuf tests PhishCase réussis : authentification/CSRF, permissions et révocation, persistance des dossiers/notes, conservation de l’original, moteur EML réel et IOC communs entre dossiers, gestion d’échecs et limites d’import, protection des anciennes routes, limitation de connexion et réinitialisation des sessions après changement de mot de passe.
- Ajout du dépôt direct avec dossiers automatiques : vrais EML et MSG, collisions de noms, échec conservé, rejet sans dossier vide, interdiction aux lecteurs, PJ téléchargées à l’identique dans le même dossier et classement prudent des signaux.
- Ruff validé sur les modules ajoutés et les tests PhishCase.
- Service démarré via Compose, uniquement sur `127.0.0.1:8088` ; accueil direct et envoi de deux emails synthétiques contrôlés dans le navigateur. Deux résultats affichés, deux dossiers nommés automatiquement, PJ présente dans le même dossier. Données synthétiques retirées après validation.
- SpamAssassin répond à PING dans le conteneur. Correction du nom utilisateur et de la journalisation hérités de l’image locale.
- Les tests du moteur réalisés sans réseau vérifient parsing et IOC ; ils ne valident pas les enrichissements tiers.

## Limites connues

Il s’agit d’une première version mono-équipe avec traitement dans la requête HTTP, pas d’une plateforme multi-tenant dotée d’une file de travaux durable. Voir le README pour le périmètre précis.

L’installation du lockfile frontend hérité signale 12 avis npm (1 faible, 4 modérés et 7 élevés). Aucune conclusion d’exploitabilité n’a été établie ici et aucune mise à jour massive des dépendances amont n’a été faite. L’image backend réutilisée et les dépendances historiques devront faire l’objet d’une revue avant exposition en production.

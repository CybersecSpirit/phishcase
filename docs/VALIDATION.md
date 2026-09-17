# Validation de la première version

- Image `phishcase:local` construite avec le contrôle TypeScript et Vite.
- Huit tests d’intégration PhishCase réussis : authentification/CSRF, permissions et révocation, persistance des dossiers/notes, conservation de l’original, moteur EML réel et IOC communs entre dossiers, gestion d’échecs et limites d’import, protection des anciennes routes, limitation de connexion et réinitialisation des sessions après changement de mot de passe.
- Ruff validé sur les modules ajoutés et les tests PhishCase.
- Service démarré via Compose, uniquement sur `127.0.0.1:8088` ; page de connexion contrôlée dans le navigateur.
- SpamAssassin répond à PING dans le conteneur. Correction du nom utilisateur et de la journalisation hérités de l’image locale.
- Les tests du moteur réalisés sans réseau vérifient parsing et IOC ; ils ne valident pas les enrichissements tiers.

## Limites connues

Il s’agit d’une première version mono-équipe avec traitement dans la requête HTTP, pas d’une plateforme multi-tenant dotée d’une file de travaux durable. Voir le README pour le périmètre précis.

L’installation du lockfile frontend hérité signale 12 avis npm (1 faible, 4 modérés et 7 élevés). Aucune conclusion d’exploitabilité n’a été établie ici et aucune mise à jour massive des dépendances amont n’a été faite. L’image backend réutilisée et les dépendances historiques devront faire l’objet d’une revue avant exposition en production.

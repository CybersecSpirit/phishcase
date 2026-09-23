# PhishCase Community Edition

**Déposez un email suspect, consultez son analyse, retrouvez les preuves dans son dossier.**

PhishCase est un espace d’investigation des emails pour une équipe de sécurité. Il accepte les fichiers **EML et MSG**, réutilise le moteur d’analyse de [eml_analyzer](https://github.com/ninoseki/eml_analyzer) et ajoute des comptes, des dossiers persistants, un tableau de bord, un historique et la corrélation des indicateurs de compromission (IOC).

L’interface est en français. Le projet est auto-hébergé et livré avec Docker Compose.

## Community et Enterprise

Ce dépôt est la **Community Edition publique et MIT** de PhishCase. Il reste utilisable seul, sans dépendance commerciale. Les fonctions SaaS/Enterprise sont développées séparément dans un dépôt privé qui référence ce cœur. Voir [l'architecture open-core](docs/OPEN_CORE.md) pour les périmètres, la relation entre dépôts et les règles de contribution.

## Parcours d’utilisation

1. Connectez-vous et ouvrez **Analyser un email**.
2. Glissez un ou plusieurs fichiers EML/MSG, ou sélectionnez-les depuis votre ordinateur.
3. Consultez le résumé de chaque analyse et ouvrez son rapport détaillé.
4. Retrouvez l’email dans **Analyses** et dans son dossier créé automatiquement.

Aucun dossier préalable n’est requis. Chaque email reçoit un dossier nommé **`date UTC d’analyse · objet du message`**, par exemple `2026-09-18 · Facture à vérifier`. Si l’objet n’est pas disponible, le nom du fichier est utilisé. Deux emails au même nom ont des dossiers distincts. Les dossiers peuvent ensuite être renommés, assignés, annotés ou complétés avec d’autres emails.

L’envoi accepte jusqu’à **20 fichiers par sélection**, de **20 Mo maximum chacun**. Les fichiers sont traités l’un après l’autre : gardez l’onglet ouvert pendant l’envoi. Après réception, les résultats sont persistants. Un email reçu dont l’analyse échoue reste dans son dossier avec son original et son état d’échec.

## Ce que contient PhishCase

| Espace | Fonctionnalités |
| --- | --- |
| Analyser un email | Dépôt direct ou multiple, progression par fichier, résumé et accès au rapport |
| Dossiers | Objet, description, priorité, statut, responsable, notes et chronologie |
| Analyses | Historique, état du traitement, en-têtes, corps du message, résultats des moteurs et pièces jointes |
| Indicateurs | URL, domaines, IP, adresses email et SHA-256 des PJ ; déduplication et liens vers les dossiers concernés |
| Vue d’ensemble | Dossiers ouverts, nombre d’analyses, IOC, échecs et activité récente |
| Mon compte | MFA par application TOTP, codes de récupération et gestion de la sécurité personnelle |
| Comptes | Création de comptes, rôles et activation/désactivation par un administrateur |

Les IOC peuvent être qualifiés manuellement : **à qualifier**, **bénin**, **suspect** ou **malveillant**. Cette qualification est partagée pour le même IOC ; elle ne remplace pas les résultats des moteurs enregistrés dans les rapports.

### Comprendre le résultat

| Résumé | Signification |
| --- | --- |
| Détection malveillante | Un service de réputation configuré, VirusTotal ou urlscan.io, signale un élément malveillant. Le rapport indique les preuves remontées. |
| Email suspect | Un ou plusieurs contrôles remontent des signaux suspects. Un score de spam, un échec DKIM ou une macro Office ne suffisent pas à confirmer un malware. |
| Aucun signal détecté | Les contrôles disponibles n’ont pas remonté de signal. Cela ne garantit pas l’innocuité du message ou de ses pièces jointes. |
| Résultat incomplet | Des contrôles attendus n’ont pas retourné de résultat. L’analyse ne permet pas de conclure. |

**« Terminée » est un état de traitement, pas un verdict de sécurité.** Consultez les détails des moteurs et la couverture disponible avant de prendre une décision.

### Pièces jointes et preuves

Les pièces jointes restent rattachées à l’analyse de leur email, **dans le même dossier**. Elles ne créent pas de dossiers séparés.

- L’original EML/MSG et son SHA-256 sont conservés.
- Les octets des PJ sont conservés dans le rapport persistant, avec leur nom, type, taille et empreintes.
- Le moteur effectue des contrôles statiques Office/OLE, notamment sur les macros et certaines structures suspectes. Une consultation de réputation par empreinte est possible si VirusTotal est configuré.
- Le fichier original et chaque PJ sont téléchargeables individuellement ; le rapport est exportable en JSON.
- Le HTML de l’email est affiché comme texte inerte. Les ressources et liens du message ne sont pas chargés automatiquement par l’interface.

**Aucune pièce jointe n’est exécutée en sandbox.** Les contrôles actuels ne constituent pas une analyse dynamique ni une couverture antivirus exhaustive de tous les formats.

## Installer sur une nouvelle machine

### Prérequis

- Git.
- Docker avec Docker Compose.
- Un accès Internet pour télécharger les images, dépendances et règles de SpamAssassin lors de la construction.

Python et Node.js sont installés dans les étapes Docker ; aucune ancienne image `eml_analyzer` ni installation Python locale n’est nécessaire.

```sh
git clone https://github.com/CybersecSpirit/phishcase.git
cd phishcase
docker compose -p phishcase -f compose.phishcase.yml up -d --build
```

Compose construit `phishcase:local` à partir des sources, puis démarre l’API, l’interface et SpamAssassin. Le premier build peut prendre plusieurs minutes.

Vérifier le service :

```sh
docker compose -p phishcase -f compose.phishcase.yml ps
docker compose -p phishcase -f compose.phishcase.yml logs --tail=100 phishcase
```

### Créer le premier administrateur

Depuis le dossier du projet, une fois le service démarré :

```sh
docker compose -p phishcase -f compose.phishcase.yml exec phishcase \
  python -m backend.investigation.store
```

1. Saisissez un **identifiant unique**, par exemple `admin`.
2. Saisissez un **mot de passe d’au moins 12 caractères**. La saisie est masquée dans le terminal.
3. Ouvrez [http://localhost:8088](http://localhost:8088) et connectez-vous avec ces identifiants.

Aucun compte ou mot de passe par défaut n’est livré. Chaque installation avec un volume vide a ses propres comptes ; les identifiants d’une autre installation ne sont pas récupérés depuis GitHub.

La commande crée un administrateur supplémentaire et **ne réinitialise pas un compte existant**. Si l’identifiant existe déjà, choisissez un autre identifiant. Les autres comptes peuvent ensuite être créés depuis **Comptes**.

### Rôles et visibilité

| Rôle | Consultation des dossiers, analyses et PJ | Modification des dossiers, analyses et IOC | Gestion des comptes |
| --- | --- | --- | --- |
| Administrateur | Oui | Oui | Oui |
| Analyste | Oui | Oui | Non |
| Lecture seule | Oui | Non | Non |

Une instance correspond à **une seule équipe**. Tous les comptes actifs peuvent consulter tous ses dossiers et preuves. L’affectation d’un responsable n’est pas une restriction d’accès par dossier.

Les mots de passe sont hachés avec scrypt. Les sessions serveur expirent après huit heures. Les écritures sont protégées contre les requêtes intersites ; les tentatives de connexion sont limitées. La modification des droits, la désactivation ou la réinitialisation du mot de passe d’un compte révoquent ses sessions.

### Activer le MFA sur son compte

Le MFA est **facultatif et individuel**, disponible pour les trois rôles. Les comptes existants restent utilisables après la mise à jour ; aucun téléphone n’est associé automatiquement.

1. Connectez-vous puis ouvrez **Mon compte → Configurer le MFA**.
2. Confirmez votre mot de passe actuel.
3. Scannez le QR code avec Aegis, Google Authenticator, Microsoft Authenticator, 1Password ou une autre application TOTP. Une clé de saisie manuelle est aussi disponible.
4. Saisissez le code à 6 chiffres pour confirmer l’activation, dans les 10 minutes.
5. **Conservez les 10 codes de récupération** dans votre gestionnaire de mots de passe. Ils ne sont affichés qu’une seule fois et peuvent être téléchargés.

Les connexions suivantes demandent le mot de passe, puis le code de l’application. En cas de perte du téléphone, choisissez **Utiliser un code de récupération** à cette deuxième étape. Chaque code de secours est utilisable une seule fois et ne remplace pas le mot de passe.

Dans **Mon compte**, vous pouvez renouveler les codes de récupération ou désactiver le MFA en fournissant votre mot de passe et un code de l’application ou de récupération. Le renouvellement invalide tous les anciens codes. Ces opérations et l’activation révoquent les autres sessions, tout en renouvelant la session courante. Changer le mot de passe depuis **Comptes** ne désactive pas le MFA.

Le TOTP utilise 6 chiffres, une période de 30 secondes et une tolérance d’une période de chaque côté. Les codes déjà acceptés sont refusés : attendez le code suivant après une activation ou une connexion. Gardez les horloges du serveur et du téléphone synchronisées. La deuxième étape expire après 5 minutes ; 5 tentatives MFA infructueuses dans une fenêtre de 15 minutes bloquent les nouvelles vérifications jusqu’à la fin de cette fenêtre, même en recommençant la connexion.

Les QR codes sont générés localement, sans service externe. Les secrets TOTP sont chiffrés avec Fernet ; seuls les hachages des codes de récupération sont conservés. L’implémentation utilise [PyOTP](https://pyauth.github.io/pyotp/). Le MFA TOTP ne fournit pas la résistance au phishing des passkeys/WebAuthn, qui ne sont pas implémentées.

Si le téléphone **et tous les codes de récupération** sont perdus, il n’existe pas de réinitialisation MFA depuis l’interface. Un opérateur disposant de l’accès au serveur peut créer un administrateur supplémentaire avec la commande documentée ci-dessus, puis désactiver l’ancien compte. Cette procédure ne récupère pas le facteur de l’ancien compte.

## Données et exploitation

Les comptes, sessions, dossiers, rapports, originaux, PJ et IOC sont conservés dans SQLite, dans le volume **`phishcase_phishcase-data`** avec les commandes ci-dessus. Le chemin du fichier est `/data/phishcase.sqlite3`.

- Un redémarrage, une reconstruction ou `docker compose ... down` conserve le volume.
- **`docker compose ... down -v` supprime le volume et ses données.**
- Les preuves et les identifiants locaux ne sont pas commités dans le dépôt.
- Une sauvegarde doit couvrir la base SQLite. Utilisez une sauvegarde SQLite cohérente ou arrêtez le service avant de copier le contenu du volume ; ne copiez pas uniquement le fichier principal pendant des écritures en mode WAL.

### Sauvegarder la clé MFA

À la première configuration MFA, une clé est créée avec des permissions `0600` à côté de la base : **`/data/phishcase.sqlite3.mfa.key`** avec le Compose fourni. Elle persiste dans le même volume. **Sauvegardez et restaurez cette clé avec la base**, avec des accès restreints. Une copie de la base seule ne permet pas de vérifier les TOTP ; les codes de récupération restent utilisables. L’application ne remplace pas silencieusement une clé perdue lorsqu’il existe des facteurs configurés.

Pour séparer la clé de la sauvegarde de la base, vous pouvez fournir `MFA_ENCRYPTION_KEY` via votre gestionnaire de secrets et l’environnement du conteneur : il doit s’agir d’une clé Fernet valide (32 octets encodés en base64 URL-safe). Configurez-la **avant la première activation MFA** et conservez-la durablement. Modifier cette valeur ne rechiffre pas les facteurs existants. Ne la commitez pas et ne la changez pas à chaque redémarrage. Le chiffrement des facteurs ne protège pas contre un accès simultané à la base et à sa clé.

### Mettre à jour

Sauvegardez les données, puis depuis une copie propre du dépôt :

```sh
git switch master
git pull --ff-only origin master
docker compose -p phishcase -f compose.phishcase.yml up -d --build
```

Gardez le même nom de projet Compose (`-p phishcase`) pour réutiliser le même volume. Les installations de développement qui utilisaient l’ancienne image locale peuvent passer au même Compose : il reconstruit désormais le moteur depuis les sources. Il n’est pas nécessaire de recréer l’administrateur si le volume existant est conservé.

### Configuration

| Variable | Usage |
| --- | --- |
| `PHISHCASE_PORT` | Port local publié, `8088` par défaut |
| `INVESTIGATION_DB` | Chemin SQLite dans le conteneur, configuré à `/data/phishcase.sqlite3` par Compose |
| `MFA_ENCRYPTION_KEY` | Facultatif : clé Fernet externe ; sinon clé persistante `INVESTIGATION_DB.mfa.key` générée automatiquement |
| `COOKIE_SECURE` | `false` dans le Compose HTTP local ; utiliser `true` derrière HTTPS |
| `SPAMASSASSIN_HOST`, `SPAMASSASSIN_PORT` | Adresse du moteur antispam ; le Dockerfile intégré utilise `127.0.0.1:7833` |
| `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `EMAIL_REP_API_KEY` | Enrichissements externes facultatifs, non configurés par défaut |

Pour changer le port local :

```sh
PHISHCASE_PORT=8090 docker compose -p phishcase -f compose.phishcase.yml up -d
```

Les variables backend supplémentaires doivent être transmises au conteneur dans `environment` ou via un `env_file` Compose, conservé hors Git. Un fichier `.env` utilisé pour l’interpolation de Compose ne transmet pas automatiquement toutes ses variables au conteneur.

Le Compose fourni publie uniquement sur **`127.0.0.1`**. Pour un accès partagé au travail, prévoir un reverse proxy HTTPS et `COOKIE_SECURE=true`, avec les règles réseau appropriées. Il n’y a pas de certificat ni d’exposition réseau d’équipe configurés automatiquement.

Les services de réputation peuvent recevoir les indicateurs consultés si leurs clés sont configurées. La consultation VirusTotal des PJ utilise leurs empreintes ; l’interface PhishCase ne soumet pas automatiquement les fichiers à VirusTotal. L’API historique conserve un endpoint de soumission explicite, protégé par les droits analyste. Consultez [la documentation du moteur amont](docs/UPSTREAM.md) pour les autres paramètres.

## Architecture et développement

- **Frontend** : Vue 3, TypeScript et Vite, construit avec Node.js 24.
- **Backend** : FastAPI, Python 3.14 et moteur `eml_analyzer`.
- **Stockage** : SQLite avec clés étrangères et mode WAL ; Redis n’est pas nécessaire au stockage des dossiers.
- **Analyse** : parsing EML/MSG, extraction des IOC, SpamAssassin, contrôles Office/OLE, DKIM et enrichissements configurés.
- **Déploiement fourni** : un conteneur avec un processus API et SpamAssassin, plus un volume persistant.

| Chemin | Contenu |
| --- | --- |
| `backend/investigation/` | Authentification, stockage, API des dossiers et synthèse des résultats |
| `backend/factories/` | Parsing et contrôles du moteur |
| `frontend/src/components/AnalysisIntake.vue` | Dépôt multiple et résultats par email |
| `frontend/src/views/WorkspaceView.vue` | Interface PhishCase |
| `tests_workspace/` | Tests des parcours PhishCase et des permissions |
| `compose.phishcase.yml` | Déploiement PhishCase recommandé |

Pour travailler hors Docker : Python 3.14, Node.js 24, `uv` et la bibliothèque système `libmagic` sont nécessaires. Installer les dépendances et construire l’interface avant d’importer l’application :

```sh
uv sync --frozen
cd frontend
npm ci
npm run build
cd ..
uv run python -m unittest discover -s tests_workspace -v
uv run ruff check backend/investigation tests_workspace
```

Les tests PhishCase utilisent des bases temporaires et vérifient le MFA (activation, connexion, rejeu, expiration, limitation, récupération, chiffrement et migration), ainsi que les permissions, l’analyse EML/MSG, la création automatique des dossiers, la conservation des preuves, les téléchargements, les échecs et la qualification prudente des résultats. Les tests historiques du moteur sont dans `tests/`. Le workflow **PhishCase checks** compile l’interface et exécute les tests dédiés sur `master`.

## Périmètre actuel

PhishCase est une première version d’investigation mono-équipe. Les limites actuelles sont :

- Traitement dans la requête HTTP avec une échéance de 180 secondes, sans file de travaux durable. Les analyses interrompues au redémarrage sont marquées en échec ; réimporter leur original pour les relancer.
- Déploiement prévu pour un seul processus API ; pas de répartition sur plusieurs workers.
- Pas d’isolation multi-organisation ou par dossier, de SSO, de passkeys/WebAuthn, de chiffrement applicatif des preuves ou de politique de rétention automatique.
- Pas de sandbox, d’export STIX ou de verdict garantissant qu’un fichier est sûr.
- Listes plafonnées à 500 dossiers/analyses, 1 000 IOC et 200 événements par dossier ; pagination complète à ajouter.

Le code et les dépendances doivent être évalués pour les exigences de votre environnement avant une exposition en production. Les vérifications réalisées sont décrites dans [docs/VALIDATION.md](docs/VALIDATION.md).

## Origine et licence

PhishCase est issu de [ninoseki/eml_analyzer](https://github.com/ninoseki/eml_analyzer), dont il conserve le moteur et la [licence MIT](LICENSE). Merci aux auteurs et contributeurs du projet amont.

Le développement initial est parti du checkout `093031e` associé à l’image locale existante. La fusion dans `master` intègre aussi les évolutions amont présentes dans le fork au commit `1f4f04b`, dont Python 3.14 et les dépendances actualisées. Le déploiement Heroku historique reste réservé au dépôt amont ; le chemin d’installation de PhishCase est `compose.phishcase.yml`.

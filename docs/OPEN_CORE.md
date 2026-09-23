# Architecture open-core de PhishCase

## Deux dépôts, un seul cœur

- [PhishCase Community](https://github.com/CybersecSpirit/phishcase) est le cœur public, auto-hébergeable, sous licence MIT.
- [PhishCase Enterprise](https://github.com/CybersecSpirit/phishcase-enterprise) est le dépôt privé destiné aux extensions commerciales, au SaaS et aux déploiements Enterprise. Son accès est réservé aux collaborateurs autorisés (un lien peut retourner 404 sans accès).

Community fonctionne et se construit seule. Elle ne dépend jamais du dépôt privé. Enterprise référence Community via le sous-module Git `community/`, verrouillé sur un commit précis ; il ne s'agit pas d'une copie du moteur ni d'un second fork à maintenir.

## Répartition du travail

| Community (public) | Enterprise (privé) |
| --- | --- |
| Analyse EML/MSG, moteur et preuves | Provisionnement et exploitation SaaS |
| Dossiers mono-équipe, IOC, comptes, rôles de base et MFA | Isolation multi-organisation et gouvernance avancée |
| Docker mono-équipe et documentation d'installation | Orchestration, quotas, plans et facturation |
| Enrichissements avec clés utilisateur et garde-fous de confidentialité | SSO entreprise, connecteurs premium, console opérateur et fonctions MSSP |
| Corrections du cœur, API et points d'extension génériques | Intégrations commerciales et configuration d'exploitation privée |

Ce tableau définit la séparation des responsabilités. Le socle Cloud dispose désormais de comptes vérifiés, organisations, PostgreSQL, quotas/offres, facturation Stripe simulée, politiques par organisation, rétention, webhooks et sauvegardes chiffrées. SSO, connecteurs premium et MSSP restent futurs. Le cœur et ses enrichissements restent publics ; le contrat de la PR draft #1 a été examiné et adapté sans fusionner cette PR.

## Dépendance et mises à jour

Enterprise choisit explicitement une révision Community et teste chaque changement du pointeur dans une PR privée. Aucun suivi automatique de `master` en production. Les correctifs génériques sont proposés à Community ; les modules commerciaux restent dans Enterprise. Ne pas développer directement dans le sous-module puis perdre les modifications lors d'un changement de révision.

Le sous-module est une solution initiale adaptée à l'application existante. Une image Docker versionnée par digest ou un package pourra le remplacer après définition des interfaces et du processus de release. Aucun registre ni package Enterprise n'est publié par cette réorganisation.

## Origine et attribution

PhishCase dérive de [ninoseki/eml_analyzer](https://github.com/ninoseki/eml_analyzer), de Manabu Niseki et de ses contributeurs. Le fichier [LICENSE](../LICENSE), incluant `Copyright (c) 2020 Manabu Niseki`, est conservé sans modification. Les notices de copyright et le texte MIT doivent accompagner les copies ou portions substantielles redistribuées, y compris dans les images ou livraisons Enterprise.

Le caractère privé d'Enterprise ne change pas la licence du cœur ni celle des contributions déjà publiques. Les conditions commerciales des nouveaux modules restent à définir ; elles ne remplacent pas les licences des composants tiers.

## Relation avec le projet amont

Le dépôt GitHub a été détaché du fork network le 23 septembre 2026, sans réécriture de l'historique. L'ascendance et l'attribution à eml_analyzer restent conservées. Pour examiner des évolutions amont dans un clone local :

```sh
git remote add upstream https://github.com/ninoseki/eml_analyzer.git
git fetch upstream
git log --oneline HEAD..upstream/master
```

Si le remote existe déjà, vérifier son URL au lieu de le recréer. Examiner et tester les changements dans une branche dédiée avant intégration ; le détachement n'effectue aucune synchronisation amont.

## État de la séparation

La release candidate enrichit le cœur public et le compose dans le dépôt privé. La PR [#1](https://github.com/CybersecSpirit/phishcase/pull/1) reste ouverte en draft et nécessite une validation avant fusion. Cloud utilise des schémas PostgreSQL et chemins de preuves sélectionnés côté serveur par organisation ; cette isolation applicative repose sur un rôle DB partagé, sans promesse de séparation OS/RLS. La logique Stripe est testée avec des doubles, sans attestation de paiement réel.

Les domaines publics sont [le site](https://phishcase.cybertactic.fr), [la documentation](https://docs.phishcase.cybertactic.fr) et [l’application](https://app.phishcase.cybertactic.fr). Le déploiement candidate Docker/Plesk est vérifié ; les inscriptions restent fermées. Restent à finaliser : SMTP réel, compte Stripe test, contact/support, documents commerciaux, calendrier et destination indépendante des sauvegardes, publication des images et validation des PR avant release stable.

## English

Community is the independent public MIT engine. The private Enterprise repository pins it as a Git submodule and builds Cloud identity, application-enforced organization isolation, plans/quotas, billing, retention, webhooks and operations around it. Generic fixes remain public. Stripe transport is currently simulated; SSO, premium connectors and MSSP are future work. The original draft PR #1 remains unmerged. Upstream eml_analyzer history and MIT attribution are retained in both distributions. Public signup stays closed until operational and commercial launch requirements are validated.

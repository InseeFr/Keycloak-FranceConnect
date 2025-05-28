# keycloak-franceconnect

[English Version](README.en.md)

- [keycloak-franceconnect](#keycloak-franceconnect)
  - [Fonctionnalités](#fonctionnalités)
  - [Compatibilité](#compatibilité)
  - [Migration](#migration)
  - [Installation](#installation)
  - [Utilisation](#utilisation)
    - [France Connect](#france-connect)
      - [Prérequis](#prérequis)
      - [Configuration](#configuration)
      - [Mappers](#mappers)
      - [Particularités de FranceConnect+](#particularités-de-franceconnect)
    - [Agent Connect](#agent-connect)
      - [Prérequis](#prérequis-1)
      - [Configuration](#configuration-1)
        - [Mappers](#mappers-1)
    - [Thème](#thème)
  - [FAQ](#faq)
  - [Comment contribuer](#comment-contribuer)


Cette extension pour [Keycloak](https://www.keycloak.org) ajoute un fournisseur d'identité permettant d'utiliser les services proposés par [France Connect](https://franceconnect.gouv.fr/).

[![CI Badge](https://github.com/InseeFr/Keycloak-FranceConnect/actions/workflows/ci.yml/badge.svg)](https://github.com/InseeFr/Keycloak-FranceConnect/actions/workflows/ci.yml)


Pour toutes questions sur l'utilisation de cette extension, n'hésitez pas à ouvrir une [discussion](https://github.com/InseeFr/Keycloak-FranceConnect/discussions).

## Fonctionnalités

* Vérification de signature (basée sur le client-secret)
* Gestion du niveau d'authentification (eIDAS) dans la demande d'autorisation (cf [communication FranceConnect](https://dev.entrouvert.org/issues/34448))
* Thèmes de connexion permettant l'affichage des boutons France Connect (fc-theme et iron-theme)
* Meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)
* Provider pour [AgentConnect](https://agentconnect.gouv.fr/)
* Gestion de FranceConnect+ (niveau EIDAS2 et EIDAS3)

## Compatibilité

- La version 7.0.0 est compatible avec Keycloak `25.0.0` et supérieur. 
- La version 6.2.0 est compatible avec Keycloak `24.x.y`. L'ihm d'administration est fonctionnelle.
- La version 6.1.0 est compatible avec Keycloak `22.0.0` jusqu'à `24.x.y`. (non configurable par ihm)
- La version 5.0.0 est compatible avec Keycloak `21.x.y`. (non configurable par ihm)
- La version 4.0.0 est compatible avec Keycloak `15.0.0` jusqu'à `20.0.0`. (non configurable par ihm à partir de keycloak 19)
- La version 2.1 jusqu'à 3.0.0 est compatible avec Keycloak `9.0.2` jusqu'à `15.0.0`.
- La version 2.0 est compatible avec Keycloak `8.0.1` jusqu'à `9.0.0`.

## Migration

Si vous utilisez déjà une ancienne version de l'extension, il est préférable de supprimer votre configuration afin d'éviter tout conflit possible.

* 2.x/3.x -> 4.x : Supprimer votre configuration de fournisseur d'identité afin que le plugin puisse générer automatiquement les mappers lors de la sauvegarde de la configuration et qu'il n'y ait aucun conflit.
* 1.x -> 2.x : Vérifiez que votre fournisseur d'identité existe et que l'environnement France Connect sélectionné est celui désiré.
* 1.x -> 1.4 : Vous devez ajouter le niveau eIDAS dans la configuration du fournisseur d'identité.

## Installation

L'installation de l'extension est simple et peut-être réalisée sans redémarrage de Keycloak.

* Téléchargez la dernière version de l'extension à partir de la page de [release](https://github.com/InseeFr/Keycloak-FranceConnect/releases)
* Copiez le fichier JAR dans le dossier `standalone/deployments` de votre serveur Keycloak
* Redémarrez Keycloak (optionnel, le déploiement à chaud devrait fonctionner)

Vous pouvez également cloner le repository Github et effectuer une installation locale avec la commande :

```
$ mvn clean install wildfly:deploy
```

## Utilisation

### France Connect

#### Environnements

Jusqu'en version 6.2.0, l'extension propose les environnement dits `V1` et `V2` qui correspondent réellement respectivement à l'offre FranceConnect standard "historique" et à l'offre FranceConnect Plus.

Suite à l'ajout de l'offre FranceConnect standard V2 et afin de lever les ambiguités, les configurations se nomment désormais `STANDARD_V2` et `PLUS_V2`, les anciens restant pendant quelques versions le temps d'effectuer la migration.
L'offre standard V1 devant s'arrêter en 2025, elle ne sera pas reprise dans les nouveaux nommages.

Chaque offre est proposée en `INTEGRATION` et en `PRODUCTION`, ce qui donne donc :

- `INTEGRATION_V1` et `PRODUCTION_V1` : Offre historique FranceConnect standard "V1" devant s'arrêter en 2025
- `INTEGRATION_V2` et `PRODUCTION_V2` : Offre FranceConnect Plus dans son ancien nommage, maintenu pour retro compatibilité
- `INTEGRATION_STANDARD_V2` et `PRODUCTION_STANDARD_V2` : Offre FranceConnect standard V2
- `INTEGRATION_STANDARD_LEGACY_V2` : Offre FranceConnect Standard V2 (à utiliser uniquement quand le client id  a été créer à partir de démarche simplifiée) *Déprécié*
- `INTEGRATION_PLUS_V2` et `PRODUCTION_PLUS_V2` : Offre FranceConnect Plus

#### Prérequis

Vous devez créer un [compte France Connect](https://franceconnect.gouv.fr/partenaires) afin de récupérer les informations nécessaires à la configuration de cette extension (clientId, clientSecret, configuration de l'url de redirection autorisée, ...). 

Il existe 2 environnements de connexion, `Integration` et `Production`. La demande d'un compte permettant l'accès à l'environnement d'Intégration s'effectue par email au service support de France Connect.

Le compte partenaire France Connect est configurable via https://partenaires.franceconnect.gouv.fr

#### Configuration

Suite à l'installation de l'extension, le fournisseur d'identité `France Connect Particulier` est apparu. Une fois ce dernier selectionné, vous arrivez sur la page de configuration suivante :

![keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.png)

Sélectionnez l'environnement désiré, entrez votre clientId, clientSecret, [les scopes](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service#identite-pivot) que vous souhaitez demander, le niveau d'authentification eIDAS.
L'alias configuré par défaut (`france-connect-particulier`) est utilisé par les thèmes `fc-theme` et `iron-theme`. Vous pouvez donc modifier le nom de l'alias si vous n'utilisez pas un de ces thèmes.

Vous trouverez également l'url de redirection qu'il faudra enregistrer sur le portail Partenaire de France Connect :
* endpoint : `https://<keycloak-url>/auth/realms/<realm>/broker/franceconnect-particulier/endpoint` 
* logout : `https://<keycloak-url>/auth/realms/<realm>/broker/franceconnect-particulier/endpoint/logout_response`

#### Mappers

Une fois la configuration validée, vous pouvez ajouter des mappers afin de récupérer les attributs à partir [des claims fournis par France Connect](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service).
Les principaux mappers sont ajoutés automatiquement lors de la création du fournisseur d'identité.

Exemples de mappers :
* Name : `lastName`, Mapper Type : `Attribute Importer`, Claim : `family_name`, User Attribute Name : `lastName`
* Name : `firstName`, Mapper Type : `Attribute Importer`, Claim : `given_name`, User Attribute Name : `firstName`
* Name : `email`, Mapper Type : `Attribute Importer`, Claim : `email`, User Attribute Name : `email`

#### Particularités de FranceConnect+

France Connect est une évolution de service pour le support des niveaux EIDAS2 et EIDAS3. Cette évolution implique un renforcement sur le niveau de confidentialité requis, ce qui se traduit par un chiffrement des jetons échangés.
Pour permettre ce chiffrement, un nouveau provider de clés à été ajouté `rsa-generated-fc+` qui permettra de générer une clé RSA et publier cette clé avec le bon algorithm sur l'url jwks de keycloak.

![](/assets/keys-provider-fc+.png)

:warning: Lors de la création de cette clé, il faut bien préciser `enc` pour l'usage de la clé.

Les informations à fournir à France Connect+ seront les suivantes :

| |  |
--|--
URL de redirection de connexion | https://*<KEYCLOAK_SERVER>*/auth/realms/*<KEYCLOAK_REALM>*/broker/franceconnect-particulier/endpoint
URL de redirection de déconnexion | https://*<KEYCLOAK_SERVER>*/auth/realms/*<KEYCLOAK_REALM>*/broker/franceconnect-particulier/endpoint?logout_response
Client keys url (jwks) | https://*<KEYCLOAK_SERVER>*/auth/realms/*<KEYCLOAK_REALM>*/protocol/openid-connect/certs
Chiffrement de l'userinfo (A256GCM / -) |  A256GCM
Algo de chiffrement de l'userinfo (ECDH-ES / RSA-OAEP) | RSA-OAEP
Algo de signature de l'userinfo (ES256 obligatoire) | ES256
Algo de signature de l'id_token (ES256 obligatoire) | ES256
Algo de chiffrement de l'id_token (ECDH-ES / RSA-OAEP) | RSA-OAEP
Chiffrement de  l'id_token  (A256GCM / -) |  A256GCM
Adresse de la clé de chiffrement (pour ouverture des flux) |  https://*<KEYCLOAK_SERVER>*/auth/realms/*<KEYCLOAK_REALM>*/protocol/openid-connect/certs

L'implémentation permettant de déchiffrer les jetons échangés s'appuie sur le travail de l'équipe keycloak autour de FAPI, cela implique que cette extension supporte uniquement Keycloak en verison supérieure à 15.
### Agent Connect

La version 3.0 de cette extension ajoute le support pour AgentConnect pour l'authentification des agents de la fonction publique d'Etat : https://github.com/france-connect/Documentation-AgentConnect.
#### Prérequis

De la même façon que pour France Connect il vous faudra demander la création d'un compte sur agent connect.

Il existe 2 environnements de connexion, `Integration` et `Production`. La demande d'un compte permettant l'accès à l'environnement d'Intégration s'effectue par email au service support d'Agent Connect.

#### Configuration

Suite à l'installation de l'extension, le fournisseur d'identité `Agent Connect` est apparu. Une fois ce dernier selectionné, vous arrivez sur la page de configuration suivante :

![keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.png)

Sélectionnez l'environnement désiré, entrez votre clientId, clientSecret, [les scopes](https://github.com/france-connect/Documentation-AgentConnect/blob/main/doc-fs.md#les-donn%C3%A9es-agent) que vous souhaitez demander, le niveau d'authentification eIDAS.
L'alias configuré par défaut (`agentconnect`) est utilisé par le thèmes `ac-theme`. Vous pouvez donc modifier le nom de l'alias si vous n'utilisez pas un de ces thèmes.

Vous trouverez également l'url de redirection qu'il faudra enregistrer sur le portail Partenaire de France Connect :
* endpoint : `https://<keycloak-url>/auth/realms/<realm>/broker/agentconnect/endpoint` 
* logout : `https://<keycloak-url>/auth/realms/<realm>/broker/agentconnect/endpoint/logout_response`

##### Mappers

Une fois la configuration validée, vous pouvez ajouter des mappers afin de récupérer les attributs à partir [des claims fournis par France Connect](https://github.com/france-connect/Documentation-AgentConnect/blob/main/doc-fs.md#les-donn%C3%A9es-agent).
Les principaux mappers sont ajoutés automatiquement lors de la création du fournisseur d'identité.

Exemples de mappers :
* Name : `lastName`, Mapper Type : `Attribute Importer`, Claim : `family_name`, User Attribute Name : `lastName`
* Name : `firstName`, Mapper Type : `Attribute Importer`, Claim : `given_name`, User Attribute Name : `firstName`
* Name : `email`, Mapper Type : `Attribute Importer`, Claim : `email`, User Attribute Name : `email`


### Thème

Cette extension fournit 1 thème :
* `fc-ac-theme`

Utilisez le thème de votre choix (selon le service que vous utilisez), et rendez-vous à l'adresse suivante : `https://<keycloak-url>/auth/realms/<realm>/account`

![keycloak-fc-login](/assets/keycloak-fc-login.png)

## FAQ

[Voir la FAQ](FAQ.md)

## Comment contribuer

[Voir ici](CONTRIBUTING.md)

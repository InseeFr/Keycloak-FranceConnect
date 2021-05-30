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
    - [Agent Connect](#agent-connect)
      - [Prérequis](#prérequis-1)
      - [Configuration](#configuration-1)
        - [Mappers](#mappers-1)
    - [Thème](#thème)
  - [FAQ](#faq)
  - [Comment contribuer](#comment-contribuer)


Cette extension pour [Keycloak](https://www.keycloak.org) ajoute un fournisseur d'identité permettant d'utiliser les services proposés par [France Connect](https://franceconnect.gouv.fr/).

[![Build Status](https://travis-ci.org/inseefr/Keycloak-FranceConnect.svg?branch=master)](https://travis-ci.org/inseefr/Keycloak-FranceConnect)

## Fonctionnalités

* Vérification de signature (basée sur le client-secret)
* Gestion du niveau d'authentification (eIDAS) dans la demande d'autorisation (cf [communication FranceConnect](https://dev.entrouvert.org/issues/34448))
* Thèmes de connexion permettant l'affichage des boutons France Connect (fc-theme et iron-theme)
* Meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)
* Provider pour [AgentConnect](https://agentconnect.gouv.fr/)

## Compatibilité

- La version 2.1 est compatible avec Keycloak `9.0.2` et supérieur.
- La version 2.0 est compatible avec Keycloak `8.0.1` jusqu'à `9.0.0`.

## Migration

Si vous utilisez déjà une ancienne version de l'extension, il est préférable de supprimer votre configuration afin d'éviter tout conflit possible.

* 1.x -> 1.4 : Vous devez ajouter le niveau eIDAS dans la configuration du fournisseur d'identité.
* 1.x -> 2.0+ : Vérifiez que votre fournisseur d'identité existe et que l'environnement France Connect sélectionné est celui désiré.

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
#### Prérequis

Vous devez créer un [compte France Connect](https://franceconnect.gouv.fr/partenaires) afin de récupérer les informations nécessaires à la configuration de cette extension (clientId, clientSecret, configuration de l'url de redirection autorisée, ...). 

Il existe 2 environnements de connexion, `Integration` et `Production`. La demande d'un compte permettant l'accès à l'environnement d'Intégration s'effectue par email au service support de France Connect.

#### Configuration

Suite à l'installation de l'extension, le fournisseur d'identité `France Connect Particulier` est apparu. Une fois ce dernier selectionné, vous arrivez sur la page de configuration suivante :

![keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.png)

Sélectionnez l'environnement désiré, entrez votre clientId, clientSecret, [les scopes](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service#identite-pivot) que vous souhaitez demander, le niveau d'authentification eIDAS.
L'alias configuré par défaut (`france-connect-particulier`) est utilisé par les thèmes `fc-theme` et `iron-theme`. Vous pouvez donc modifier le nom de l'alias si vous n'utilisez pas un de ces thèmes.

Vous trouverez également l'url de redirection qu'il faudra enregistrer sur le portail Partenaire de France Connect :
* endpoint : `https://<keycloak-url>/auth/realms/<realm>/broker/franceconnect-particulier/endpoint` 
* logout : `https://<keycloak-url>/auth/realms/<realm>/broker/franceconnect-particulier/endpoint/logout_response`

##### Mappers

Une fois la configuration validée, vous pouvez ajouter des mappers afin de récupérer les attributs à partir [des claims fournis par France Connect](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service).

Exemples de mappers :
* Name : `lastName`, Mapper Type : `Attribute Importer`, Claim : `family_name`, User Attribute Name : `lastName`
* Name : `firstName`, Mapper Type : `Attribute Importer`, Claim : `given_name`, User Attribute Name : `firstName`
* Name : `email`, Mapper Type : `Attribute Importer`, Claim : `email`, User Attribute Name : `email`

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

Exemples de mappers :
* Name : `lastName`, Mapper Type : `Attribute Importer`, Claim : `family_name`, User Attribute Name : `lastName`
* Name : `firstName`, Mapper Type : `Attribute Importer`, Claim : `given_name`, User Attribute Name : `firstName`
* Name : `email`, Mapper Type : `Attribute Importer`, Claim : `email`, User Attribute Name : `email`


### Thème

Cette extension fournit 2 thèmes :
* `fc-theme`
* `iron-theme`
* `ac-theme` 

Utilisez le thème de votre choix (selon le service que vous utilisez), et rendez-vous à l'adresse suivante : `https://<keycloak-url>/auth/realms/<realm>/account`

![keycloak-fc-login](/assets/keycloak-fc-login.png)

## FAQ

[Voir la FAQ](FAQ.md)

## Comment contribuer

[Voir ici](CONTRIBUTING.md)

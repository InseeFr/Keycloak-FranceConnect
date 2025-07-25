# keycloak-franceconnect

- [keycloak-franceconnect](#keycloak-franceconnect)
  - [Features](#features)
  - [Compatibility](#compatibility)
  - [Migration](#migration)
  - [Installation](#installation)
  - [How to use it](#how-to-use-it)
    - [Requirements](#requirements)
    - [Configuration](#configuration)
      - [Mappers](#mappers)
      - [Theme](#theme)
  - [Q&A](#qa)
  - [How to contribute](#how-to-contribute)

This [Keycloak](https://www.keycloak.org) plugin adds an identity provider allowing to use [France Connect](https://franceconnect.gouv.fr/) services.

[![CI Badge](https://github.com/InseeFr/Keycloak-FranceConnect/actions/workflows/ci.yml/badge.svg)](https://github.com/InseeFr/Keycloak-FranceConnect/actions/workflows/ci.yml)

## Features

* Signature verification (based on client-secret)
* User account warranty level (eIDAS) required on authorization request (cf [communication FranceConnect](https://dev.entrouvert.org/issues/34448))
* Login themes with FranceConnect buttons (fc-theme and iron-theme)
* Better management for logout (https://issues.jboss.org/browse/KEYCLOAK-7209)

## Compatibility

* The version 7.0.0 of this plugin is compatible with Keycloak `25.0.0` and higher.
* The version 6.2.0 of this plugin is compatible with Keycloak `24.x.y`. It's configurable with UI.
* The version 6.1.0 of this plugin is compatible with Keycloak `22.0.0` until `24.x.y`. (not configurable with UI)
* The version 5.0.0 of this plugin is compatible with Keycloak `21.x.y`. (not configurable with UI)
* The version 4.0.0 of this plugin is compatible with Keycloak `15.0.0` until `20.0.0`. (not configurable with UI starting keycloak 19)
* The version 2.1 up to 3.0.0 of this plugin is compatible with Keycloak `9.0.2` until `15.0.0`.
* The version 2.0 of this plugin is compatible with Keycloak `8.0.1` until `9.0.2`.

## Migration

If you are already using an older version of the plugin, it's better to delete your configuration to avoid any conflict.

* 2.x/3.x -> 4.x : Delete your identity provider configuration so that the plugin can automatically generate the mappers when saving the configuration and that there are no conflict.
* 1.x -> 2.x: Check that your identity provider still exists and that the selected France Connect environment is good
* 1.x -> 1.4: You will need to configure the new eIDAS level in the configuration

## Installation

The plugin installation is simple and can be done without a Keycloak server restart.

* Download the latest release from the [releases page](https://github.com/InseeFr/Keycloak-FranceConnect/releases)
* Copy the JAR file into the `standalone/deployments` directory in your Keycloak server's root
* Restart Keycloak (optional, hot deployment should work)

You can also clone the Github Repository and install the plugin locally with the following command:

```
$ mvn clean install wildfly:deploy
```

## How to use it

### Environments

Up until version 6.2.0, the extension provided the so-called V1 and V2 environments, which correspond respectively to the historical FranceConnect "standard" and the FranceConnect Plus.

With the addition of the FranceConnect standard V2 and to clear up any ambiguities, the configurations are now named `STANDARD_V2` and `PLUS_V2`, while the previous ones will remain available for a few versions to allow for migration. Since the standard V1 offering will be discontinued in 2025, it will not be included in the new naming conventions.

Each offering is available in both INTEGRATION and PRODUCTION, resulting in the following:

- `INTEGRATION_V1` and `PRODUCTION_V1` : Historical FranceConnect standard "V1", which will be discontinued in 2025
- `INTEGRATION_V2` and `PRODUCTION_V2` : FranceConnect Plus under its old naming, maintained for backward compatibility
- `INTEGRATION_STANDARD_V2` and `PRODUCTION_STANDARD_V2` : FranceConnect standard V2
- `INTEGRATION_STANDARD_LEGACY_V2`: FranceConnect V2, has to be used only when your client id has been created with "Démarche simplifiée" *Deprecated*
- `INTEGRATION_PLUS_V2` and `PRODUCTION_PLUS_V2` : FranceConnect Plus

### Requirements

You must have a [France Connect account](https://franceconnect.gouv.fr/partenaires) to retrieve plugin configuration information (clientId, clientSecret, authorized redirect uri, ...)

There are 2 environments, `Integration` and `Production`. The request for an Integration account is made by email to the France Connect support team.

France Connect account can be managed at https://partenaires.franceconnect.gouv.fr

### Configuration

Once the installation is complete, the `France Connect Particulier` identity provider appears. Once selected, you can see the following configuration page:

![keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.png)

Choose the France Connect environment, enter your clientId, clientSecret, requested [scopes](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service#identite-pivot), the eIDAS authentication level.  
The configured alias (`france-connect-particulier`) is used by `fc-theme` and `iron-theme` themes. You can rename this alias if you don't use one of theses themes.

You will also find the redirect uri you will need to enter on the France Connect partner portal:
* endpoint: `https://<keycloak-url>/auth/realms/<realm>/broker/franceconnect-particulier/endpoint` 
* logout: `https://<keycloak-url>/auth/realms/<realm>/broker/franceconnect-particulier/endpoint/logout_response`

#### Mappers

Once the configuration validated, you can add the mappers needed to retrieve the attributes you want from [claims provided by France Connect](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service).
The main mappers are automatically added when creating the identity provider.

Mappers examples:
* Name : `lastName`, Mapper Type : `Attribute Importer`, Claim : `family_name`, User Attribute Name : `lastName`
* Name : `firstName`, Mapper Type : `Attribute Importer`, Claim : `given_name`, User Attribute Name : `firstName`
* Name : `email`, Mapper Type : `Attribute Importer`, Claim : `email`, User Attribute Name : `email`

#### Theme

This plugin provides 1 theme:
* `fc-ac-theme`

Choose your theme and go to the following url: `https://<keycloak-url>/auth/realms/<realm>/account`

![keycloak-fc-login](/assets/keycloak-fc-login.png)

## Q&A

[See Q&A](FAQ.md)

## How to contribute

[See here](CONTRIBUTING.en.md)

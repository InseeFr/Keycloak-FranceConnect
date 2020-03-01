# keycloak-franceconnect

This [Keycloak](https://www.keycloak.org) plugin adds an identity provider allowing to use [France Connect](https://franceconnect.gouv.fr/) services.

[![Build Status](https://travis-ci.org/inseefr/Keycloak-FranceConnect.svg?branch=master)](https://travis-ci.org/inseefr/Keycloak-FranceConnect)

## Features

* Signature verification (based on client-secret)
* User account warranty level (eIDAS) required on authorization request (cf [communication FranceConnect](https://dev.entrouvert.org/issues/34448))
* Login themes with FranceConnect buttons (fc-theme and iron-theme)
* Better management for logout (https://issues.jboss.org/browse/KEYCLOAK-7209)

## Compatibility

This plugin is compatible with Keycloak `8.0.1.Final` and higher.

## Migration

If you are already using an older version of the plugin, it's better to delete your configuration to avoid any conflict.

* 1.x -> 1.4: You will need to configure the new eIDAS level in the configuration
* 1.x -> 1.5: Check that your identity provider still exists and that the selected France Connect environment is good

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

### Requirements

You must have a [France Connect account](https://franceconnect.gouv.fr/partenaires) to retrieve plugin configuration information (clientId, clientSecret, authorized redirect uri, ...)

There are 2 environments, `Integration` and `Production`. The request for an Integration account is made by email to the France Connect support team.

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

Mappers examples:
* Name : `lastName`, Mapper Type : `Attribute Importer`, Claim : `family_name`, User Attribute Name : `lastName`
* Name : `firstName`, Mapper Type : `Attribute Importer`, Claim : `given_name`, User Attribute Name : `firstName`
* Name : `email`, Mapper Type : `Attribute Importer`, Claim : `email`, User Attribute Name : `email`

#### Theme

This plugin provides 2 themes:
* `fc-theme`
* `iron-theme`

Choose your theme and go to the following url: `https://<keycloak-url>/auth/realms/<realm>/account`

![keycloak-fc-login](/assets/keycloak-fc-login.png)

## Q&A

[See Q&A](FAQ.md)

## How to contribute

[See here](CONTRIBUTING.en.md)

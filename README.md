# keycloak-franceconnect

France Connect Openid-Connect Provider for Keycloak

## Features

* add missing signature verification (based on client-secret)
* add custom Theme with FranceConnect buttons
* add a better management for logout

## How to use it

Simply drop the generated jar in `$keycloak_home/standalone/deployment`
or with a local install :

```
mvn clean install wildfly:deploy
```

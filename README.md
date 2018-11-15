# keycloak-franceconnect

Extension keycloak pour faciliter l'usage de France Connect

## Fonctionnalités

* ajout de la vérification de signature (basée sur le cleint-secret)
* ajout d'un theme pour afficher les boutons france connect
* meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)

## Utilisation

Placer le jar dans `$keycloak_home/standalone/deployment`
ou avec une installation locale de keycloak:

```
mvn clean install wildfly:deploy
```



---

# keycloak-franceconnect

France Connect Openid-Connect Provider for Keycloak

## Features

* add missing signature verification (based on client-secret)
* add custom Theme with FranceConnect buttons
* add a better management for logout (https://issues.jboss.org/browse/KEYCLOAK-7209)

## How to use it

Simply drop the generated jar in `$keycloak_home/standalone/deployment`
or with a local install :

```
mvn clean install wildfly:deploy
```

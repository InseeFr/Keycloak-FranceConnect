# keycloak-franceconnect

Extension [keycloak](https://www.keycloak.org) pour faciliter l'usage de France Connect

## Fonctionnalités

* ajout de la vérification de signature (basée sur le client-secret)
* ajout d'un theme pour afficher les boutons france connect
* meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)

## Utilisation

Vous aurez besoin du logiciel [keycloak](https://www.keycloak.org) dans une version supérieure à la 4.5.0.Final.
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

You will need [keycloak](https://www.keycloak.org) > 4.5.0.Final
Simply drop the generated jar in `$keycloak_home/standalone/deployment`
or with a local install :

```
mvn clean install wildfly:deploy
```

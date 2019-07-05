# keycloak-franceconnect

[English Version](README.en.md)

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

:warning: Il y avait un problème avec la version `4.8.0.Final` de keycloak, cette dernière n'est pas compatible avec cette extension (la version 4.8.1.Final l'est).

Une fois le jar déployé, vous pouvez créer un nouveau "Identity Provider" (dans un nouveau realm préférablement). Dans la liste déroulante, vous avez le choix entre deux providers qui représentent l'environnement de production et l'environnement de test france connect. Ce dernier est utilisable avec un compte créé sur https://partenaires.franceconnect.gouv.fr/.

Une fois choisi le provider, vous arrivez sur la page suivante:

![keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.PNG)

Vous pouvez changer les paramètres comme vous le souhaitez, excepté pour l'alias qui doit rester celui ci, dans le cas où vous souhaitez profiter du theme offert par cette extension (dans le cas contraire, vous pouvez le modifier comme bon vous semble).

Sur cette page se trouve aussi l'uri de redirection qu'il vous faudra entrer sur le portail partenaire de France Connect (ici : `http://localhost:8080/auth/realms/franceconnect/broker/franceconnect-particulier-test/endpoint`). L'uri de redirection pour le logout se construit à partir de la précedente en rajoutant `/logout_response` (ici : `http://localhost:8080/auth/realms/franceconnect/broker/franceconnect-particulier-test/endpoint/logout_response`).

Une fois validé, vous pouvez ajouter les mappers nécessaires pour récupérer les attributs que vous souhaitez à partir [des claims fournis par France Connect](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service).

Pour tester, vous pouvez choisir le theme `fc-theme` pour le realm, puis vous rendre sur l'adresse : `https://<keycloak>/auth/realms/<realm>/account` : 

![keycloak-fc-login](/assets/keycloak-fc-login.PNG)

## Comment contribuer

[Voir ici](CONTRIBUTING.md)
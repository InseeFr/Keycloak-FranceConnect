# keycloak-franceconnect

[English Version](README.en.md)

Extension [keycloak](https://www.keycloak.org) pour faciliter l'usage de France Connect

## Fonctionnalités

* ajout de la vérification de signature (basée sur le client-secret)
* ajout d'un theme pour afficher les boutons france connect
* meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)
* gestion du niveau d'authentification dans la demande d'autorisation ( cf [communication FranceConnect](https://dev.entrouvert.org/issues/34448) )

## Utilisation

Vous aurez besoin du logiciel [keycloak](https://www.keycloak.org) dans une version supérieure à la 4.5.0.Final.
Placer le jar dans `$keycloak_home/standalone/deployments`
ou avec une installation locale de keycloak:

```
mvn clean install wildfly:deploy
```

:warning: Il y avait un problème avec la version `4.8.0.Final` de keycloak, cette dernière n'est pas compatible avec cette extension (la version 4.8.1.Final l'est).

Une fois le jar déployé, vous pouvez créer un nouveau "Identity Provider" (dans un nouveau realm préférablement). Dans la liste déroulante, vous avez le choix entre deux providers qui représentent l'environnement de production et l'environnement de test france connect. Ce dernier est utilisable avec un compte créé sur https://partenaires.franceconnect.gouv.fr/.

:warning: Si vous migrez et que vous disposez déjà d'un "Identity Provider" configuré, vous devez impérativement configurer le niveau eIDAS dans sa configuration.

Une fois le provider choisi, vous arrivez sur la page suivante:

![keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.PNG)

Vous pouvez changer les paramètres comme vous le souhaitez, excepté pour l'alias qui doit rester celui ci, dans le cas où vous souhaitez profiter du theme offert par cette extension (dans le cas contraire, vous pouvez le modifier comme bon vous semble).

Sur cette page se trouve aussi l'uri de redirection qu'il vous faudra entrer sur le portail partenaire de France Connect (ici : `http://localhost:8080/auth/realms/franceconnect/broker/franceconnect-particulier-test/endpoint`). L'uri de redirection pour le logout se construit à partir de la précedente en rajoutant `/logout_response` (ici : `http://localhost:8080/auth/realms/franceconnect/broker/franceconnect-particulier-test/endpoint/logout_response`).

Une fois validé, vous pouvez ajouter les mappers nécessaires pour récupérer les attributs que vous souhaitez à partir [des claims fournis par France Connect](https://partenaires.franceconnect.gouv.fr/fcp/fournisseur-service).

Pour tester, vous pouvez choisir le theme `fc-theme` pour le realm, puis vous rendre sur l'adresse : `https://<keycloak>/auth/realms/<realm>/account` : 

![keycloak-fc-login](/assets/keycloak-fc-login.PNG)

## Intégration du bouton FranceConnect dans votre theme

Pour intégrer le design du bouton FranceConnect, il faut ajouter les classes CSS suivante à votre thème :

```
a.zocial.franceconnect-particulier-test,
a.zocial.franceconnect-particulier
{
    background: url(https://partenaires.franceconnect.gouv.fr/images/fc_bouton_alt2_v2.png) no-repeat left top;
    height: 70px;
    width: auto;
    padding-top: 60px;
}

a.zocial.franceconnect-particulier-test:hover,
a.zocial.franceconnect-particulier:hover {
    background: url(https://partenaires.franceconnect.gouv.fr/images/fc_bouton_alt3_v2.png) no-repeat left top !important;
    height: 70px;
    width: auto;
}

a.zocial.franceconnect-particulier-test span,
a.zocial.franceconnect-particulier span{
    display:none;
}
```

## FAQ

[FAQ](FAQ.md)

## Comment contribuer

[Voir ici](CONTRIBUTING.md)

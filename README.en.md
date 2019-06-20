
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

:warning: There was a problem with keycloak version `4.8.0.Final`, please use `4.8.1.Final`


Once the jar has been deployed, you can create a new "Identity Provider" (in a new realm preferably). In the drop-down list, you can choose between two providers that represent the production environment and the france connect test environment. The latter can be used with an account created on https://partenaires.franceconnect.gouv.fr/.

Once chosen the provider, you arrive on the following page:

![Keycloak-fc-conf-provider](/assets/keycloak-fc-conf-provider.PNG)

You can change the settings as you want, except for the alias that must remain this one, in case you want to take advantage of the theme offered by this extension (if not, you can change it as you see fit).

On this page is also the redirection uri you will need to enter on the France Connect partner portal (here: `http://localhost:8080/auth/realms/franceconnect/broker/franceconnect-particular-test/endpoint`). The redirection uri for the logout is built from the previous one by adding `/logout_response` (here:`http://localhost:8080/auth/realms/franceconnect/broker/franceconnect-particular-test/endpoint/logout_response `).

Once validated, you can add the mappers needed to retrieve the attributes you want from [claims provided by France Connect] (https://partenaires.franceconnect.gouv.fr/fcp/profisseur-service).

To test, you can choose the theme `fc-theme` for the realm, then go to the address:` https://<keycloak>/auth/realms/<realm>/account`:

![Keycloak-fc-login](/assets/keycloak-fc-login.PNG)

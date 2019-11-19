
## Log user profile details

:warning: do not use this in production!

First, you need to activate debug on this class :

```
$  <KC-DIR>/bin/jboss-cli.sh --connect
[standalone@localhost:9990 /] /subsystem=logging/logger=org.keycloak.social.user_profile_dump:add()
[standalone@localhost:9990 /] /subsystem=logging/logger=org.keycloak.social.user_profile_dump:write-attribute(name="level", value="DEBUG")
```

Then tail the serverlog file : 
 
```
$ tail -50f <KC-DIR>/standalone/log/server.log
...
2019-11-08 16:54:07,648 DEBUG [org.keycloak.social.user_profile_dump] (default task-26) User Profile JSON Data for provider FC-Prov-Test: {"sub":"e3ed09176995319363efe042c0ac632807f5fd049845bebf76515d2b1493201fv1","given_name":"Angela Claire Louise","family_name":"DUBOIS","gender":"female","birthdate":"1962-08-24","preferred_username":"","birthplace":"75107","birthcountry":"99100","phone_number":"0123456789","email":"wossewodda-3728@yopmail.com","address":{"country":"France","formatted":"France Paris 75107 20 avenue de Ségur","locality":"Paris","postal_code":"75107","street_address":"20 avenue de Ségur"}}
...
```

You find here the claim name that you can use to add "" mappers in order to store user information in Keycloak user attributes  
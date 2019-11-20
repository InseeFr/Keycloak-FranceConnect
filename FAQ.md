
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

## Retrieving the France Connect access_token

Keycloak is able to store the tokens from France Connect. Those tokens can be accessed by any clients to request data providers.

To do that, you will need to configure the provider to store tokens and enable the rights for users to read those tokens, this is done like this :

![store-tokens](/assets/store-tokens.png)

To retrieve the token from keycloak, you cant do a request like :

```http
GET /auth/realms/{realm}/broker/{provider_alias}/token HTTP/1.1
Host: {keycloak_host}
Authorization: Bearer <KEYCLOAK ACCESS TOKEN>
```

with provider_alias the alias you chose for the france connect provider. The response is something like:

```json
{
	"access_token": "49357726-38d8-43eb-9cd5-ebc1f9241569",
	"expires_in": 60,
	"refresh_expires_in": 0,
	"token_type": "Bearer",
	"id_token": "eyJ0eXA[...]Ap6w8jteXEYml2z_Jg",
	"not-before-policy": 0,
	"accessTokenExpiration": 1574257750
}

```

With `access_token` the token you can use to call data providers. 
For example, you can use the France Connect endpoint to validate the token :

```http
POST https://fcp.integ01.dev-franceconnect.fr/api/v1/checktoken HTTP/1.1
Content-Type: application/json

{"token": "49357726-38d8-43eb-9cd5-ebc1f9241569"}

---

HTTP/1.1 200 OK
Server: nginx
Date: Wed, 20 Nov 2019 12:01:23 GMT   
Content-Type: application/json; charset=utf-8    
Content-Length: 658     
Connection: keep-alive  
Vary: Accept-Encoding   
ETag: W/"292-fbZV9XPGUnzK7aJJqL17bA"  
Vary: Accept-Encoding   
Strict-Transport-Security: max-age=15768000      
        

{
  "scope": [   
    "openid",  
    "identite_pivot", 
    "email",   
    "address", 
    "phone"    
  ],      
  "identity": {
    "given_name": "Angela Claire Louise", 
    "family_name": "DUBOIS",       
    "birthdate": "1962-08-24",     
    "gender": "female",            
    "birthplace": "75107",         
    "birthcountry": "99100",       
    "preferred_username": "",      
    "email": "wossewodda-3728@yopmail.com",                 
    "address": { 
      "country": "France",
      "formatted": "France Paris 75107 20 avenue de Ségur", 
      "locality": "Paris",
      "postal_code": "75107",      
      "street_address": "20 avenue de Ségur"       
    },    
    "phone_number": "0123456789",  
    "_claim_names": {},   
    "_claim_sources": {   
      "src1": {} 
    }     
  },      
  "client": {  
    "client_id": "8436aea4c7d3da8341c605d284e2d0512d76e0a24f633f8642016a44a189cdfd", 
    "client_name": "Test Keycloak" 
  },      
  "acr": "eidas2"
}


```
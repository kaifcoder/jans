---
tags:
  - administration
  - developer
  - script-catalog
  - UMA
  - RPTPolicy
---



# UMA RPT Policy (Client Authorization)

This custom UMA RPT policy script allows RPT access only for specific clients. It uses the `allowed_clients` configuration attribute to define a comma-separated list of authorized client IDs.

## Inherited Methods

| Method header | Method description |
|:-----|:------|
| `def init(self, customScript, configurationAttributes)` | Called once during initialization. Used to set up client whitelist from configuration. |
| `def destroy(self, configurationAttributes)` | Called on script shutdown for cleanup. |
| `def getApiVersion(self)` | Returns the API version used by the script.|
|`def getRequiredClaims(self, context)`| Defines claims required to access a resource. This script returns an empty claim set.|
|`def authorize(self, context)`| Main method that checks if the requesting client is in the allowed list. Returns `True` to authorize, `False` otherwise.|
|`def getClaimsGatheringScriptName(self, context)`|Returns the name of the claim gathering script to use (if any). This script returns UmaConstants.NO_SCRIPT.|

## Objects

| Object name | Object description |
|:-----|:------|
| `customScript` | The custom script object. [Reference](https://github.com/JanssenProject/jans/blob/main/jans-core/script/src/main/java/io/jans/model/custom/script/model/CustomScript.java) |
| `configurationAttributes` | A `Map<String, SimpleCustomProperty>` of script-level configuration properties. |
| `context` |  The authorization context. Reference: [UmaAuthorizationContext.java](https://github.com/JanssenProject/jans/blob/main/jans-auth-server/server/src/main/java/io/jans/as/server/uma/authorization/UmaAuthorizationContext.java) |


## Configuration
The script uses a single required configuration property:



| Property | Description |
|:-----|:------|
|`allowed_clients`| Comma-separated list of client IDs (DNS values) that are allowed to obtain an RPT token. |


## Script Type: Python

```python
    from io.jans.as.model.uma import UmaConstants
    from io.jans.model.uma import ClaimDefinitionBuilder
    from io.jans.model.custom.script.type.uma import UmaRptPolicyType
    from io.jans.service.cdi.util import CdiUtil
    from io.jans.util import StringHelper, ArrayHelper
    from java.util import Arrays, ArrayList, HashSet
    from java.lang import String

    class UmaRptPolicy(UmaRptPolicyType):

        def __init__(self, currentTimeMillis):
            self.currentTimeMillis = currentTimeMillis

        def init(self, customScript, configurationAttributes):
            print "RPT Policy. Initializing ..."
            self.clientsSet = self.prepareClientsSet(configurationAttributes)
            print "RPT Policy. Initialized successfully"
            return True

        def destroy(self, configurationAttributes):
            print "RPT Policy. Destroyed successfully"
            return True

        def getApiVersion(self):
            return 11

        def getRequiredClaims(self, context):
            json = """[
            ]"""
            return ClaimDefinitionBuilder.build(json)

        def authorize(self, context): # context is reference of io.jans.as.uma.authorization.UmaAuthorizationContext
            print "RPT Policy. Authorizing ..."

            client_id=context.getClient().getClientId()
            print "UmaRptPolicy. client_id = %s" % client_id

            if (StringHelper.isEmpty(client_id)):
                return False
        
            if (self.clientsSet.contains(client_id)):
                print "UmaRptPolicy. Authorizing client"
                return True
            else:
                print "UmaRptPolicy. Client isn't authorized"
                return False

        def getClaimsGatheringScriptName(self, context):
            return UmaConstants.NO_SCRIPT

        def prepareClientsSet(self, configurationAttributes):
            clientsSet = HashSet()
            if (not configurationAttributes.containsKey("allowed_clients")):
                return clientsSet

            allowedClientsList = configurationAttributes.get("allowed_clients").getValue2()
            if (StringHelper.isEmpty(allowedClientsList)):
                print "UmaRptPolicy. The property allowed_clients is empty"
                return clientsSet    

            allowedClientsListArray = StringHelper.split(allowedClientsList, ",")
            if (ArrayHelper.isEmpty(allowedClientsListArray)):
                print "UmaRptPolicy. No clients specified in allowed_clients property"
                return clientsSet
            
            # Convert to HashSet to quick search
            i = 0
            count = len(allowedClientsListArray)
            while (i < count):
                client = allowedClientsListArray[i]
                clientsSet.add(client)
                i = i + 1

            return clientsSet
```







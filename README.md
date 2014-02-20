AAF Rapid Connect Fascinator SSO Plugin
====

This plugin integrates AAF Rapid Connect to your build. Please see: https://rapid.aaf.edu.au/

This plugin is purely an authentication plugin, authorization (roles) will have to be managed by an appropriate roles plugin like the Internal Roles Plugin.

Installation
==== 

Please add the ff. dependency to your institutional build's pom.xml:

	<!--  Rapid AAF SSO plugin -->
	<dependency>
		<groupId>au.com.redboxresearchdata.fascinator</groupId>
		<artifactId>plugin-sso-rapidaaf</artifactId>
		<version>your-desired-version</version>
	</dependency>

Then, further on the same file, under "build"->"plugins"->"maven-dependency-plugin", add the ff. execution:

 	 <!-- RapidAAF Resources -->
      <execution>
          <id>unpack-rapidaaf-conf</id>
          <phase>process-resources</phase>
          <goals>
              <goal>unpack</goal>
          </goals>
          <configuration>
              <outputDirectory>${project.home}</outputDirectory>
              <artifactItems>
                  <artifactItem>
                      <groupId>au.com.redboxresearchdata.fascinator</groupId>
					  <artifactId>plugin-sso-rapidaaf</artifactId>
                      <classifier>rapidaaf-config</classifier>
                      <type>zip</type>
                  </artifactItem>
              </artifactItems>
          </configuration>
      </execution>
      
 Next, update your build's system-config.json, adding the top-level entry:
 
	 "rapidAafSso": {
	    	"url":"",
	    	"sharedKey":"",
	    	"aud":"${server.url.base}",
	    	"iss":"https://rapid.test.aaf.edu.au",
	    	"attrParentField":"https://aaf.edu.au/attributes",
	    	"usernameField":"edupersontargetedid",
	    	"source":"rapidAafSso"    	
	 },
	 
You will need to replace the "url" and "sharedKey" values specific to your institution, and are specified during service registration. See AAF Rapid Connect documentation for details. 

Please note that when registering a service, make sure to specify the "<YourBaseUrl>/auth/jwt.script" in the "Callback URL" field. Also, the "aud" config value must match the "URL" field value entered during registration.  

Optionally, you might also want to modify the "iss" field to reflect the appropriate environment. 

Then, on the same file, add the plugin identifier on the SSO configuration:

	"sso": {
        "plugins": ["rapidAafSso"],

Finally, tell the Internal Roles plugin the default role, like so:

	"roles": {
        "type": "internal",
        "internal": {
            "path": "${fascinator.home}/security/roles.properties",
            "defaultRoles":["guest"]
        }
    },

Please note that this plugin is not dependent on the Internal Roles plugin. Whichever plugin you may select, you will need to configure it to assign a default role whenever user does not have one assigned.

That's it folks!



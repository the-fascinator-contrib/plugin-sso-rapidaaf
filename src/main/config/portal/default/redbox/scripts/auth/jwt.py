# Copyright (C) 2014 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from com.nimbusds.jose import JWSObject
from com.nimbusds.jose.crypto import MACVerifier
from java.lang import String
from java.util import Date, HashMap
from com.googlecode.fascinator.common import JsonSimple
from com.googlecode.fascinator.spring import ApplicationContextProvider

class JwtData():
    def __init__(self):
        pass
    
    def __activate__(self, context):
        self.velocityContext = context
        self.log = self.vc("log")
        self.systemConfig = self.vc("systemConfig")        
        self.formData = context["formData"]
        self.assertionText = self.formData.get("assertion")
        self.session = self.vc("sessionState")
        self.response = self.vc("response")
        self.request = self.vc("request")
        method = self.request.getMethod()
        
        #checking access method
        if method != "POST":
            self.log.error("Page not accessed by a POST, method:%s" % method)
            return
        
        self.sharedKey = String(self.systemConfig.getString("", "rapidAafSso", "sharedKey"))
        self.aud = self.systemConfig.getString("", "rapidAafSso", "aud")
        self.iss = self.systemConfig.getString("", "rapidAafSso", "iss")
        
        #checking signature
        jwsObject = JWSObject.parse(self.assertionText)        
        verifier = MACVerifier(self.sharedKey.getBytes())                        
        verifiedSignature = jwsObject.verify(verifier)
        
        if (verifiedSignature):
            self.log.debug("Verified JWS signature!")
        else:            
            self.log.error("Invalid JWS signature!")                                    
            return
        
        self.log.debug(jwsObject.getPayload().toString())
        self.log.debug(self.session.toString())
            
        json = JsonSimple(jwsObject.getPayload().toString())
        aud = json.getString("", "aud")
        iss = json.getString("", "iss")
        nbf = json.getInteger(None, "nbf")
        exp = json.getInteger(None, "exp")
        jti = json.getString("", "jti")
          
        #checking aud
        if self.aud != aud:
            self.log.error("Invalid aud: '%s' expecting: '%s'" % (aud, self.aud))
            return  
        
        #checking iss
        if self.iss != iss:
            self.log.error("Invalid iss: '%s' expecting: '%s'" % (iss, self.iss))
            return
        
        #checking times
        now = Date().getTime() / 1000
        if now < nbf or now > exp:
            self.log.error("Invalid timings.")
            return
        
        #checking jti
        attributeDao = ApplicationContextProvider.getApplicationContext().getBean("hibernateAuthUserAttributeDao")
        params = HashMap()
        params.put("key", "jti")
        params.put("value", jti)
        attrList = attributeDao.query("getUserAttributeByKeyAndValue", params)
        if attrList.size() > 0:
            self.log.error("Possible replay attack, jti:'%s' found in DB." % jti)
            return        
        
        self.session.put("jwt", jwsObject.getPayload().toString())
        self.session.put("jwt_json", json)
        self.session.put("jwt_assertion", self.assertionText)
        self.session.put("jwt_exp", exp)        
        self.returnAddress = self.session.get("returnAddress")
        if self.returnAddress is None:
            self.log.debug("No return address, using portalPath.")
            self.returnAddress = self.vc("portalPath")
        self.log.debug("RapidAAF SSO login complete, redirect to: %s" % self.returnAddress)                        
        self.response.sendRedirect(self.returnAddress)            
        
    # Get from velocity context
    def vc(self, index):
        if self.velocityContext[index] is not None:
            return self.velocityContext[index]
        else:
            self.velocityContext["log"].error("ERROR: Requested context entry '{}' doesn't exist", index)
            return None
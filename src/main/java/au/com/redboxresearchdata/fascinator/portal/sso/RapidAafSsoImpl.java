/*******************************************************************************
 * Copyright (C) 2014 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 ******************************************************************************/
package au.com.redboxresearchdata.fascinator.portal.sso;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.googlecode.fascinator.api.authentication.User;
import com.googlecode.fascinator.common.JsonSimple;
import com.googlecode.fascinator.common.JsonSimpleConfig;
import com.googlecode.fascinator.portal.JsonSessionState;
import com.googlecode.fascinator.portal.sso.SSOInterface;

/**
 * 
 * @author Shilo Banihit
 *
 */
public class RapidAafSsoImpl implements SSOInterface {
	
	private static final Logger logger = LoggerFactory.getLogger(RapidAafSsoImpl.class);
	private Template template;
	private String rapidAafUrl;
	private String attrParentField;
	private String usernameField;
	private String source;
	private JsonSimple ssoConfig;
	private List<String> emptyRoles = new ArrayList<String>();

	static final String ID = "rapidAafSso";
	static final String LABEL = "AAF Rapid Connect";
	
	public RapidAafSsoImpl()
	{
		logger.debug("RapidAafSsoImpl init...");
		try {
			if(Velocity.getProperty(Velocity.FILE_RESOURCE_LOADER_PATH) != null) {
	    		logger.debug(String.format("Resource Loader Path: %s", Velocity.getProperty(Velocity.FILE_RESOURCE_LOADER_PATH).toString()));
	    		template = Velocity.getTemplate("rapidaaf/interface.vm");
	    	}
	        JsonSimpleConfig config = new JsonSimpleConfig();
	        ssoConfig = new JsonSimple(config.getObject(ID));
	        
	        rapidAafUrl = ssoConfig.getString("", "url");
	        attrParentField = ssoConfig.getString("", "attrParentField");
	        usernameField = ssoConfig.getString("", "usernameField");
	        source = ssoConfig.getString("", "source");
	        	        
		} catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
		logger.debug("RapidAafSsoImpl init...done");
	}
	
	@Override
	public String getId() {
		logger.debug("RapidAafSsoImpl returning ID.");
		return ID;
	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#getLabel()
	 */
	@Override
	public String getLabel() {
		logger.debug("RapidAafSsoImpl returning Label.");
		return LABEL;
	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#getInterface(java.lang.String)
	 */
	@Override
	public String getInterface(String ssoUrl) {		
		logger.trace(String.format("ssoGetInterface: %s", ssoUrl));
        StringWriter sw = new StringWriter();
        VelocityContext vc = new VelocityContext();
        try {    
        	vc.put("rapidaaf_url", ssoUrl.replace("default/sso", "default/sso/"+ID));
            template.merge(vc, sw);
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
        return sw.toString();
     }

	/**
	 * Returning an empty list since the roles plugin will take care of it.
	 * 
	 * TODO: deprecate this method in the future
	 */
	@Override
	public List<String> getRolesList(JsonSessionState session) {		
		return emptyRoles;
	}

	/**
	 * Non-null return value means the user has valid credentials. The assumption is that the JWT script has executed already and had set the necessary session parameters.
	 * 
	 */
	@Override
	public User getUserObject(JsonSessionState session) {
		RapidAafUser user = (RapidAafUser) session.get("jwt_user");
		long now = new Date().getTime() / 1000;
		if (user == null) {
			JsonSimple jwt_json =  (JsonSimple) session.get("jwt_json");
			Integer jwt_exp = (Integer) session.get("jwt_exp");
			if (jwt_json == null || jwt_exp == null) {
				logger.error("Session does not have jwt_json or jwt_exp, might be expired.");
				return null;					
			}			
			if (now > jwt_exp.longValue()) {
				logger.error("Session has expired, exp: " + jwt_exp + ", now:" + now);
				return null;
			}		
			String username = jwt_json.getString(null, attrParentField, usernameField);
			if (username == null) {
				logger.error("JWT has no username attribute: "+attrParentField + "->" + usernameField);
				return null;
			}
			String realName = jwt_json.getString(username, attrParentField, "displayname");
			user = new RapidAafUser(realName);
			// set the attributes...
			user.setUsername(username);			
			user.set("jti", jwt_json.getString("", "jti"));
			user.set("exp", jwt_exp.toString());
			List<String> userFieldNames = ssoConfig.getStringList("userFields");
			for (String userFieldName : userFieldNames) {
				String fieldVal = jwt_json.getString(null,  attrParentField, userFieldName);
				if (fieldVal != null) {
					logger.debug("Setting '"+userFieldName+"' with value: " + fieldVal);
					user.set(userFieldName, fieldVal);					
				} else {
					logger.debug("Skipping setting of " + userFieldName + ", null value.");
				}
			}
			
			// commented out saving since HibernateUserAttribute value column is too short for it.
			//user.set("jwt", (String) session.get("jwt"));
			user.setSource(source);
			// put the user on the session
			session.put("jwt_user", user);
		} 
		return user;
	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#logout(com.googlecode.fascinator.portal.JsonSessionState)
	 */
	@Override
	public void logout(JsonSessionState session) {
		session.remove("jwt_user");
		session.remove("jwt");
		session.remove("jwt_assertion");
		session.remove("jwt_json");
		session.remove("jwt_exp");
		session.remove("username");
		session.remove("source");
	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#ssoInit(com.googlecode.fascinator.portal.JsonSessionState, javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public void ssoInit(JsonSessionState session, HttpServletRequest request)
			throws Exception {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#ssoCheckUserDetails(com.googlecode.fascinator.portal.JsonSessionState)
	 */
	@Override
	public void ssoCheckUserDetails(JsonSessionState session) {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#ssoGetRemoteLogonURL(com.googlecode.fascinator.portal.JsonSessionState)
	 */
	@Override
	public String ssoGetRemoteLogonURL(JsonSessionState session) {
		return rapidAafUrl;
	}

	/* (non-Javadoc)
	 * @see com.googlecode.fascinator.portal.sso.SSOInterface#ssoPrepareLogin(com.googlecode.fascinator.portal.JsonSessionState, java.lang.String, java.lang.String)
	 */
	@Override
	public void ssoPrepareLogin(JsonSessionState session, String returnAddress,
			String server) throws Exception {
		// TODO Auto-generated method stub

	}
}

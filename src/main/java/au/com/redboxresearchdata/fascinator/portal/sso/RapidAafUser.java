/**
 * 
 */
package au.com.redboxresearchdata.fascinator.portal.sso;

import com.googlecode.fascinator.common.JsonSimple;
import com.googlecode.fascinator.common.authentication.GenericUser;

/**
 * 
 * @author Shilo Banihit
 *
 */
public class RapidAafUser extends GenericUser {
	
	public String realName;
	
	public RapidAafUser(String realName) {		
		this.realName = realName;		
	}
	
	@Override
    public String realName() {
		return realName;
	}
}

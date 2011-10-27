/**
 * 
 */
package de.bund.bsi.animamea.asn1;

import de.bund.bsi.animamea.asn1.bc.SecurityInfos;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface PrivilegedTerminalInfoInterface {
	
	public String getProtocolOID();
	public SecurityInfos getSecurityInfos();

}

/**
 * 
 */
package de.tsenger.animamea.asn1;

import de.tsenger.animamea.asn1.bc.SecurityInfos;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface PrivilegedTerminalInfoInterface {
	
	public String getProtocolOID();
	public SecurityInfos getSecurityInfos();

}

/**
 * 
 */
package de.bund.bsi.animamea.asn1;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface ChipAuthenticationDomainParameterInfoInterface {
	
	public String getProtocolOID();
	public AlgorithmIdentifier getDomainParameter();
	public int getKeyId();

}

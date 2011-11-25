/**
 * 
 */
package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;



/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface PaceDomainParameterInfoInterface {
	
	public String getProtocolOID();
	public AlgorithmIdentifier getDomainParameter();
	/**
	 * @return Returns -1 if the optional field parameterID is not used.
	 */
	public int getParameterId();

}

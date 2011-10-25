/**
 * 
 */
package de.bund.bsi.animamea.asn1;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface ChipAuthenticationDomainParameterInfoInterface {
	
	public String getProtocolString();
	public byte[] getProtocolBytes();
	public byte[] getDomainParameter();
	public int getKeyId();

}

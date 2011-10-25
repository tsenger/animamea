/**
 * 
 */
package de.bund.bsi.animamea.asn1;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface ChipAuthenticationInfoInterface {
	
	public String getProtocolString();
	public byte[] getProtocolBytes();
	public int getVersion();
	public int keyId();
	
}

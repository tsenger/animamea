/**
 * 
 */
package de.bund.bsi.animamea.asn1;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface FileIDInterface {
	
	public byte[] getFID();
	/**
	 * @return Returns -1 if the optional field sfid is not used.
	 */
	public byte getSFID();

}

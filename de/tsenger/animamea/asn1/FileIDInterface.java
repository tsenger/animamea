/**
 * 
 */
package de.tsenger.animamea.asn1;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface FileIDInterface {
	
	public byte[] getFID();
	/**
	 * @return Returns -1 if the optional field sfid is not used.
	 */
	public byte getSFID();

}

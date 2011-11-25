/**
 * 
 */
package de.tsenger.animamea.asn1;

import de.tsenger.animamea.asn1.bc.FileID;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface CardInfoLocatorInterface {
	
	public String getOID();
	public String getUrl();
	public FileID getFileID();

}

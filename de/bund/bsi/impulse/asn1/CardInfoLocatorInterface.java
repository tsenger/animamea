/**
 * 
 */
package de.bund.bsi.impulse.asn1;

import de.bund.bsi.impulse.asn1.bc.FileID;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface CardInfoLocatorInterface {
	
	public String getOID();
	public String getUrl();
	public FileID getFileID();

}

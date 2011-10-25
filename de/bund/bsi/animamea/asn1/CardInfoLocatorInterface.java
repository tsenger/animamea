/**
 * 
 */
package de.bund.bsi.animamea.asn1;

import de.bund.bsi.animamea.asn1.bc.FileID;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface CardInfoLocatorInterface {
	
	public String getOID();
	public String getUrl();
	public FileID getFileID();

}

/**
 * 
 */
package de.bund.bsi.animamea.asn1;

import de.bund.bsi.animamea.asn1.bc.FileID;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface TerminalAuthenticationInfoInterface {

	public String getProtocolOID();
	public int getVersion();
	public FileID getEFCVCA();

}

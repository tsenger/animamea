/**
 * 
 */
package de.tsenger.animamea.asn1;

import de.tsenger.animamea.asn1.bc.FileID;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface TerminalAuthenticationInfoInterface {

	public String getProtocolOID();
	public int getVersion();
	public FileID getEFCVCA();

}

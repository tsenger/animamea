/**
 * 
 */
package de.bund.bsi.impulse.asn1;

import de.bund.bsi.impulse.asn1.bc.FileID;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public interface TerminalAuthenticationInfoInterface {

	public String getProtocolString();
	public byte[] getProtocolBytes();
	public int getVersion();
	public FileID getEFCVCA();

}

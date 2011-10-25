/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.TerminalAuthenticationInfoInterface;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class TerminalAuthenticationInfo implements TerminalAuthenticationInfoInterface{

	private DERObjectIdentifier protocol = null;
	private DERInteger version = null;
	private DERSequence fileID = null;
	
	/**
	 * @param derSequence
	 */
	public TerminalAuthenticationInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger)seq.getObjectAt(1);
		if (seq.size()>2) {
			fileID = (DERSequence)seq.getObjectAt(2);
		}
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.TerminalAuthenticationInfoInterface#getProtocolString()
	 */
	@Override
	public String getProtocolString() {
		return protocol.toString();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.TerminalAuthenticationInfoInterface#getProtocolBytes()
	 */
	@Override
	public byte[] getProtocolBytes() {
		return protocol.getDEREncoded();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.TerminalAuthenticationInfoInterface#getVersion()
	 */
	@Override
	public int getVersion() {
		return version.getValue().intValue();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.TerminalAuthenticationInfoInterface#getEFCVCA()
	 */
	@Override
	public FileID getEFCVCA() {
		if (fileID==null) return null;
		else return new FileID(fileID);
	}

}

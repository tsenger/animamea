/**
 * 
 */
package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class TerminalAuthenticationInfo {

	private DERObjectIdentifier protocol = null;
	private DERInteger version = null;
	private DERSequence fileID = null;
	
	/**
	 * @param derSequence
	 * @throws Exception Throws Exception if FileId is used with version 2
	 */
	public TerminalAuthenticationInfo(DERSequence seq) throws Exception {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger)seq.getObjectAt(1);
		if (seq.size()>2) {
			fileID = (DERSequence)seq.getObjectAt(2);
		}
		if (version.getValue().intValue()==2&&fileID!=null) throw new Exception("FileID MUST NOT be used for version 2!");
	}


	public String getProtocolOID() {
		return protocol.toString();
	}


	public int getVersion() {
		return version.getValue().intValue();
	}


	public FileID getEFCVCA() {
		if (fileID==null) return null; //optionales Feld FileID nicht vorhanden.
		else return new FileID(fileID);
	}
	
	@Override
	public String toString() {
		return "TerminalAuthenticationInfo\n\tOID: " + getProtocolOID() + "\n\tVersion: " + getVersion() + "\n\tEF.CVCA: " + getEFCVCA() + "\n";
	}

}

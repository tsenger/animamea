/*
 * FileID
 */

package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.FileIDInterface;
import de.bund.bsi.animamea.tools.HexString;


/**
 *
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 */
public class FileID implements FileIDInterface {
	
	private DEROctetString fid = null;
	private DEROctetString sfid = null;

	public FileID(DERSequence seq) {
		fid = (DEROctetString) seq.getObjectAt(0);
		if (seq.size()>1) {
			sfid = (DEROctetString)seq.getObjectAt(1);
		}
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.FileIDInterface#getFID()
	 */
	@Override
	public byte[] getFID() {
		return fid.getOctets();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.FileIDInterface#getSFID()
	 */
	@Override
	public byte getSFID() {
		if (sfid!=null) return (sfid.getOctets()[0]);
		else return -1; // optionales Feld sfid ist nicht vorhanden
	}
	
	@Override
	public String toString() {
		return "FileID \n\tFID: " + HexString.bufferToHex(getFID()) + "\n\tSFID: " + getSFID()+"\n";
	}
	
}

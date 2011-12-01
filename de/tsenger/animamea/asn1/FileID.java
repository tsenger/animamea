/*
 * FileID
 */

package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import de.tsenger.animamea.tools.HexString;


/**
 *
 * @author Tobias Senger (tobias@t-senger.de)
 */
public class FileID {
	
	private DEROctetString fid = null;
	private DEROctetString sfid = null;

	public FileID(DERSequence seq) {
		fid = (DEROctetString) seq.getObjectAt(0);
		if (seq.size()>1) {
			sfid = (DEROctetString)seq.getObjectAt(1);
		}
	}

	public byte[] getFID() {
		return fid.getOctets();
	}

	public byte getSFID() {
		if (sfid!=null) return (sfid.getOctets()[0]);
		else return -1; // optionales Feld sfid ist nicht vorhanden
	}
	
	@Override
	public String toString() {
		return "FileID \n\tFID: " + HexString.bufferToHex(getFID()) + "\n\tSFID: " + getSFID()+"\n";
	}
	
}

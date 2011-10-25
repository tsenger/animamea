/*
 * FileID
 */

package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.FileIDInterface;


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
			sfid = (DEROctetString)seq.getObjectAt(2);
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
		return (sfid.getOctets()[0]);
	}
	
}

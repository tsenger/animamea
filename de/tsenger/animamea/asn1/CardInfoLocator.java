/*
 * CardInfoLocator
 * OID: 0.4.0.127.0.7.2.2.6
 */

package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

;

/**
 *
 * @author Tobias Senger (tobias@t-senger.de)
 */
public class CardInfoLocator {
	
	private DERObjectIdentifier protocol = null;
	private DERIA5String url = null;
	private DERSequence fileID = null;

	public CardInfoLocator(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		url = (DERIA5String)seq.getObjectAt(1);
		if (seq.size()>2) {
			fileID = (DERSequence)seq.getObjectAt(2);
		}
	}


	public String getOID() {
		return protocol.getId();
	}


	public String getUrl() {
		return url.getString();
	}


	public FileID getFileID() {
		if (fileID==null) return null;
		else return new FileID(fileID);
	}
	
	@Override
	public String toString() {
		return "CardInfoLocator \n\tOID: " + getOID() + "\n\tURL: " +getUrl() + "\n\t" + getFileID()+"\n";
		
	}


}

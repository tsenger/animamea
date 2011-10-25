/*
 * CardInfoLocator
 * OID: 0.4.0.127.0.7.2.2.6
 */

package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.CardInfoLocatorInterface;

;

/**
 *
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 */
public class CardInfoLocator implements CardInfoLocatorInterface{
	
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

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.CardInfoLocatorInterface#getOID()
	 */
	@Override
	public String getOID() {
		return protocol.getId();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.CardInfoLocatorInterface#getUrl()
	 */
	@Override
	public String getUrl() {
		return url.getString();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.CardInfoLocatorInterface#getFileID()
	 */
	@Override
	public FileID getFileID() {
		if (fileID==null) return null;
		else return new FileID(fileID);
	}


}

/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import de.bund.bsi.animamea.asn1.ChipAuthenticationInfoInterface;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class ChipAuthenticationInfo implements ChipAuthenticationInfoInterface{

	private DERObjectIdentifier protocol = null;
	private DERInteger version = null;
	private DERInteger keyId = null;
	
	public ChipAuthenticationInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger)seq.getObjectAt(1);
		
		if (seq.size()>2) {
			keyId = (DERInteger)seq.getObjectAt(2);
		}
	}
	
	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationInfoInterface#getProtocolString()
	 */
	@Override
	public String getProtocolOID() {
		return protocol.toString();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationInfoInterface#getVersion()
	 */
	@Override
	public int getVersion() {
		return version.getValue().intValue();
	}

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.asn1.ChipAuthenticationInfoInterface#keyId()
	 */
	@Override
	public int getKeyId() {
		if (keyId==null) return -1; //optionales Feld keyId nicht vorhanden
		else return keyId.getValue().intValue();
	}
	
	@Override
	public String toString() {
		return "ChipAuthenticationInfo \n\tOID: " + getProtocolOID() + "\n\tVersion: " + getVersion() + "\n\tKeyId: " + getKeyId() +"\n";
	}

}

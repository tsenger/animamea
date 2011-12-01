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
public class ChipAuthenticationInfo{

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
	
	
	public String getProtocolOID() {
		return protocol.toString();
	}


	public int getVersion() {
		return version.getValue().intValue();
	}

	
	public int getKeyId() {
		if (keyId==null) return -1; //optionales Feld keyId nicht vorhanden
		else return keyId.getValue().intValue();
	}
	
	@Override
	public String toString() {
		return "ChipAuthenticationInfo \n\tOID: " + getProtocolOID() + "\n\tVersion: " + getVersion() + "\n\tKeyId: " + getKeyId() +"\n";
	}

}

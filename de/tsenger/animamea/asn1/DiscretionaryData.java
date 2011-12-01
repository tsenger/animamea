/**
 * 
 */
package de.tsenger.animamea.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DiscretionaryData {
	
	private DERApplicationSpecific dData = null;
	
	
	public DiscretionaryData(byte[] authorization) throws IOException {
		DEROctetString auth = new DEROctetString(authorization);
		dData = new DERApplicationSpecific(false, 0x13, auth);
	}
	
	public DiscretionaryData(byte authorization) throws IOException {
		DERInteger auth = new DERInteger(authorization);
		dData = new DERApplicationSpecific(false, 0x13, auth);
	}

	
	public DERObject toASN1Object() {
		return dData;
	}
	
	public byte[] getEncoded() {
		return dData.getDEREncoded();
	}

}

/**
 * 
 */
package de.bund.bsi.animamea.asn1.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class DiscretionaryData extends ASN1Encodable {
	
	private DERApplicationSpecific dData = null;
	
	
	public DiscretionaryData(byte[] authorization) throws IOException {
		DEROctetString auth = new DEROctetString(authorization);
		dData = new DERApplicationSpecific(false, 0x13, auth);
	}
	
	public DiscretionaryData(byte authorization) throws IOException {
		DERInteger auth = new DERInteger(authorization);
		dData = new DERApplicationSpecific(false, 0x13, auth);
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public DERObject toASN1Object() {
		return dData;
	}

}

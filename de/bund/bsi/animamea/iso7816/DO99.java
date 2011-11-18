/**
 * 
 */
package de.bund.bsi.animamea.iso7816;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 * 
 */
public class DO99 extends DERTaggedObject {

	private static final byte[] DEFAULT_VALUE = new byte[0];
	private byte[] value_ = DEFAULT_VALUE;
	ASN1TaggedObject to = null;
	DEROctetString ocs = null;
	DERInteger dint = null;

	// Konstruktor zum Decoden
	public DO99() {
		super(0x19);
	}

	// Konstruktor zum Encoden
	public DO99(byte[] le) {
		super(false, 0x19, new DEROctetString(le));
	}
	

	public void decode(byte[] encodedData) {
		
		try {
			to = (ASN1TaggedObject) super.fromByteArray(encodedData);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
		ocs = (DEROctetString) to.getObject();
		value_ = ocs.getOctets();

	}
	
    @Override
	public byte[] getEncoded() {
    	try {
			return to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return null;
    }

	public byte[] getData() {
		return value_;
	}
}

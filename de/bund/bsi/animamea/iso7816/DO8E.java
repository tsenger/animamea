/**
 * 
 */
package de.bund.bsi.animamea.iso7816;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class DO8E extends DERTaggedObject {
	
	private static final byte[] DEFAULT_VALUE = new byte[0];
    private byte[] value_ = DEFAULT_VALUE;
    DERTaggedObject to = null;
    DEROctetString ocs = null;
	
	//Konstruktor zum Decoden
	public DO8E(){
		super(0x1E);
	}
	
	//Konstruktor zum Encoden
	public DO8E(byte[] checksum){
		super(false, 0x1E, new DEROctetString(checksum));
	}
	
	public void decode(byte[] encodedData) {
    	ASN1InputStream asn1in = new ASN1InputStream(encodedData);
    	try {
			to = (DERTaggedObject)asn1in.readObject();
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

package de.bund.bsi.animamea.iso7816;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;



public class DO97 extends DERTaggedObject{
	
	private static final byte[] DEFAULT_VALUE = new byte[0];
    private byte[] value_ = DEFAULT_VALUE;
    DERTaggedObject to = null;
    DEROctetString ocs = null;
    DERInteger dint = null;
	
    //Konstruktor zum Decoden
	public DO97(){
		super(0x17);
	}
	
	//Konstruktor zum Encoden
	public DO97(byte[] le) {
		super(false, 0x17, new DEROctetString(le));
	}
	
	//Konstruktor zum Encoden
	public DO97(int le) {
		super(false, 0x17, new DERInteger(le));
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

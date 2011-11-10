package de.bund.bsi.animamea.iso7816;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;



public class DO87 extends DERTaggedObject{
	
	private static final byte[] DEFAULT_VALUE = new byte[0];
    private byte[] value_ = DEFAULT_VALUE;
    DERTaggedObject to = null;
    DEROctetString ocs = null;
	
    //Konstruktor zum Decoden
	public DO87(){
		super(7);
	}
	
	//Konstruktor zum Encoden
	public DO87(byte[] data) {
		super(false, 7, new DEROctetString(data));
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
 

    
    public byte[] getData() {
    	return value_;
    }


}

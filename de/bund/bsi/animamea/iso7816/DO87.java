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
    byte[] encodedData = null;
	
    //Konstruktor zum Decoden
	public DO87(){
		super(7);
	}
	
	//Konstruktor zum Encoden
	public DO87(byte[] data) {
		super(false, 7, new DEROctetString(addOne(data)));
		try {
			encodedData = super.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private  byte[] addOne(byte[] data) {
		byte[] ret = new byte[data.length+1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
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
		this.encodedData = encodedData;
    }
    
    @Override
	public byte[] getEncoded() {
    	return encodedData;
    }
 

    
    public byte[] getData() {
    	byte[] ret = new byte[value_.length-1];
		System.arraycopy(value_, 1, ret, 0, ret.length);
		return ret;
    }


}

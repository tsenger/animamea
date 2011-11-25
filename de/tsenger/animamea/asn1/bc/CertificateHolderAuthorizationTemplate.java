package de.tsenger.animamea.asn1.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;


public class CertificateHolderAuthorizationTemplate  {
	
    private DERObjectIdentifier id_role = null;
    private DiscretionaryData auth = null;
    private DERApplicationSpecific chat = null;
  
    
    public CertificateHolderAuthorizationTemplate(DERObjectIdentifier role, DiscretionaryData disData) {
    	this.id_role = role;
    	this.auth = disData;
    	
    	ASN1EncodableVector v = new ASN1EncodableVector();
    	v.add(id_role);
    	v.add(auth.toASN1Object());
    	    	
    	this.chat = null;
		this.chat = new DERApplicationSpecific(0x4c, v);
    }


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	public DERObject toASN1Object() {
			
		return chat;
	}
	
	public byte[] getEncoded() {
		try {
			return chat.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}

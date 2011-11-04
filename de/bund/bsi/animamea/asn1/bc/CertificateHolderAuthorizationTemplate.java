package de.bund.bsi.animamea.asn1.bc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;


public class CertificateHolderAuthorizationTemplate extends ASN1Encodable {
	
    private DERObjectIdentifier id_role = null;
    private DiscretionaryData auth = null;
  
    
    public CertificateHolderAuthorizationTemplate(DERObjectIdentifier role, DiscretionaryData disData) {
    	this.id_role = role;
    	this.auth = disData;
    }


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
    	v.add(id_role);
    	v.add(auth);
    	    	
    	DERApplicationSpecific chat = null;
		chat = new DERApplicationSpecific(0x4c, v);
		
		return chat;
	}

}

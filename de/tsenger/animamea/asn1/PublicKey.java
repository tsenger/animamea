package de.tsenger.animamea.asn1;

import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

public class PublicKey {

	
    private DERObjectIdentifier oid06 = null;
    private DERTaggedObject y84 = null;
    private DERTaggedObject Y86 = null;
 
    private DERApplicationSpecific publicKey = null;
    

    //TODO Konstruktor für PublicKey erweitern siehe D.3 in BSI TR-03110
    
    /** 
     * Konstruktor für PublicKey für PACE und ChipAuthentication Version 2
     * @param oidString Algorithm Identifier beeinhaltet die OID des verwendeten Algorithmus
     * @param publicPoint Domain Parameter des verwendeten PACE-Protokolls 
     * @throws Exception 
     */
    public PublicKey(String oidString, byte[] publicKeyData) throws Exception {
    	
    	oid06 = new DERObjectIdentifier(oidString);
    	
    	ASN1EncodableVector vec = new ASN1EncodableVector();
    	vec.add(oid06);
    	
    	if (oidString.startsWith(id_PACE_DH_GM.toString())||oidString.startsWith(id_PACE_DH_IM.toString())) {
    		y84 = new DERTaggedObject(false, 4, new DEROctetString(publicKeyData));
    		vec.add(y84);
    	}
		else if (oidString.startsWith(id_PACE_ECDH_GM.toString())||oidString.startsWith(id_PACE_ECDH_IM.toString())) {
			Y86 = new DERTaggedObject(false, 6, new DEROctetString(publicKeyData));
			vec.add(Y86);
		}

		else throw new Exception("Unknown Protocol OID");
    	
    	publicKey = new DERApplicationSpecific(0x49, vec);
		
    }
    

 	
    
    /** Liefert ein ASN1-kodierted Byte-Array des PublicKeys zurück
     * @return 
     * @throws IOException 
    */
    public byte[] getEncoded() throws IOException {
    	   
		return publicKey.getEncoded();
    }
}
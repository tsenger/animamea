/**
 *  Copyright 2011, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.tsenger.animamea.asn1;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class ECPrivateKey extends ASN1Encodable {
	
	private BigInteger version = null;
	private DEROctetString privateKey = null;
	private X9ECParameters parameters = null; 	// OPTIONAL
    private X9ECPoint publicKey = null;			// OPTIONAL
    
    
    public static ECPrivateKey getInstance(ASN1TaggedObject obj, boolean explicit) {
            return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ECPrivateKey getInstance(Object  obj) {
    	if (obj instanceof ECPrivateKey) {
    		return (ECPrivateKey)obj;
        }
        else if (obj != null) {
        	return new ECPrivateKey(ASN1Sequence.getInstance(obj));
        }
    	return null;
    }

	/**
	 * 
	 */
	public ECPrivateKey(ASN1Sequence seq) {	
		
		Enumeration e = seq.getObjects();
		
		version = ((DERInteger)e.nextElement()).getValue();
		if (version.intValue() != 1) {
			throw new IllegalArgumentException("wrong version for ECPrivateKey");
		}
		
		privateKey = (DEROctetString)e.nextElement();
		
		if (e.hasMoreElements()) {
			parameters = (X9ECParameters) e.nextElement();
		}
		
		if (e.hasMoreElements()) {
			publicKey = (X9ECPoint) e.nextElement();
		}
	}
	
	public byte[] getPrivateKey() {
		return privateKey.getOctets();
	}
	
	public X9ECParameters getParameters() {
		return parameters;
	}
	
	public X9ECPoint getPublicKey() {
		return publicKey;
	}

	/**
     * write out an EC private key with its associated information
     * as described in RFC 5915.
     * <pre>
     *		ECPrivateKey ::= SEQUENCE {
     *			version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *			privateKey     OCTET STRING,
     *			parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *			publicKey  [1] BIT STRING OPTIONAL
   	 *		}
     * </pre>
     */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERInteger(0));
		v.add(privateKey);
		
		if(parameters!=null) {
			v.add(parameters);
		}
		
		if(publicKey!=null) {
			v.add(publicKey);
		}
		
		return new DERSequence(v);
	}

}

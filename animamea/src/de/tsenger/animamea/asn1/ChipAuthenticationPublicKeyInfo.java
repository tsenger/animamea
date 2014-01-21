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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 * The ChipAuthenticationPublicKeyInfo object.
 * <pre>
 * ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
 *   protocol						OBJECT IDENTIFIER{id-PK-DH | id-PK-ECDH},
 *   chipAuthenticationPublicKey    SubjectPublicKeyInfo,
 *   keyID							INTEGER OPTIONAL
 * }
 * </pre>
 */
public class ChipAuthenticationPublicKeyInfo extends ASN1Object{
	
	private ASN1ObjectIdentifier protocol = null;
	private SubjectPublicKeyInfo capk = null;
	private ASN1Integer keyId = null;
	
	public ChipAuthenticationPublicKeyInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		capk = new SubjectPublicKeyInfo((ASN1Sequence)seq.getObjectAt(1));
		if (seq.size()==3) {
			keyId = (ASN1Integer)seq.getObjectAt(2);
		}	
	}
	
	public ASN1ObjectIdentifier getProtocol() {
		return protocol;
	}
	
	public SubjectPublicKeyInfo getPublicKey() {
		return capk;
	}
	
	public int getKeyId() {
		if (keyId == null)
			return -1; // optionales Feld keyId nicht vorhanden
		else
			return keyId.getPositiveValue().intValue();
	}
	
	@Override
	public String toString() {
		return "ChipAuthenticationPublicKeyInfo \n\tprotocol: "
				+ getProtocol() + "\n\tSubjectPublicKeyInfo: \n\t\t"
				+ "Algorithm: "+ getPublicKey().getAlgorithm().getAlgorithm() + "\n\t\t"
				+ "AmPublicKey:" + HexString.bufferToHex(getPublicKey().getPublicKey()) + 
				(keyId!=null?"\n\tKeyId " + keyId.getPositiveValue().intValue() + "\n":"\n");
	}
	
	
	/**
	 * The definition of ChipAuthenticationPublicKeyInfo is
     * <pre>
     * ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
     *      protocol					OBJECT IDENTIFIER(id-PK-DH | id-PK-ECDH),
     *      chipAuthenticationPublicKey	SubjectPublicKeyInfo,
     *      keyID						INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(protocol);
		vec.add(capk);
		if (keyId!=null) {
			vec.add(keyId);
		}
		return ASN1Sequence.getInstance(vec);
	}
	
	

}

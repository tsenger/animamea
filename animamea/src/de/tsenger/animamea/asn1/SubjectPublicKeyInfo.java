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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class SubjectPublicKeyInfo extends ASN1Object {
	
	private AlgorithmIdentifier algorithm = null;
	private DERBitString subjectPublicKey = null;

	/**
	 * @param seq
	 */
	public SubjectPublicKeyInfo(ASN1Sequence seq) {
		algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
		subjectPublicKey = DERBitString.getInstance((seq.getObjectAt(1)));
	}
	
	public AlgorithmIdentifier getAlgorithm() {
		return algorithm;
	}
	
	public byte[] getPublicKey() {
		return subjectPublicKey.getBytes();
	}

	/** 
	 * The SubjectPublicKeyInfo object.
	 * <pre>
	 * SubjectPublicKeyInfo ::= SEQUENCE {
	 *   algorithm			AlgorithmIdentifier,
	 *   subjectPublicKey	BIT STRING
	 * }
	 * </pre>
	 * 
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(algorithm);
		vec.add(subjectPublicKey);
		return ASN1Sequence.getInstance(vec);
	}

}

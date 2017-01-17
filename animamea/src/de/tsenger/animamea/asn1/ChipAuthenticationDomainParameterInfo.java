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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class ChipAuthenticationDomainParameterInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private ASN1Integer keyId = null;

	/**
	 * @param ASN1Sequence
	 */
	public ChipAuthenticationDomainParameterInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

		if (seq.size() > 2) {
			keyId = (ASN1Integer) seq.getObjectAt(2);
		}
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public AlgorithmIdentifier getDomainParameter() {
		return domainParameter;
	}

	public int getKeyId() {
		if (keyId == null)
			return -1; // optionales Feld keyId nicht vorhanden
		else
			return keyId.getPositiveValue().intValue();
	}

	@Override
	public String toString() {
		return "ChipAuthenticationDomainParameterInfo \n\tOID: "
				+ getProtocolOID() + "\n\tDomainParameter: \n\t\t"
				+ getDomainParameter().getAlgorithm() + "\n\t\t"
				+ getDomainParameter().getParameters() + 
				(keyId!=null?"\n\tKeyId " + keyId.getPositiveValue().intValue() + "\n":"\n");
	}

	/**
	 * The definition of ChipAuthenticationDomainParameterInfo is
     * <pre>
     * ChipAuthenticationDomainParameterInfo ::= SEQUENCE {
     *      protocol   			OBJECT IDENTIFIER(id-id_CA-DH | id-id_CA-ECDH),
     *      domainParameter		AlgorithmIdentifier,
     *      keyID				INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(domainParameter); 
		if (keyId!=null) v.add(keyId);
		
		return ASN1Sequence.getInstance(v);
	}

}

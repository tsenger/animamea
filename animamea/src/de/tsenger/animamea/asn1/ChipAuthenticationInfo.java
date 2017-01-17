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

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class ChipAuthenticationInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private ASN1Integer version = null;
	private ASN1Integer keyId = null;

	public ChipAuthenticationInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		version = (ASN1Integer) seq.getObjectAt(1);

		if (seq.size() > 2) {
			keyId = (ASN1Integer) seq.getObjectAt(2);
		}
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public int getKeyId() {
		if (keyId == null)
			return -1; // optionales Feld keyId nicht vorhanden
		else
			return keyId.getPositiveValue().intValue();
	}


	@Override
	public String toString() {
		return "ChipAuthenticationInfo \n\tOID: " + getProtocolOID()
				+ "\n\tVersion: " + getVersion() + 
				(keyId!=null?"\n\tKeyId " + keyId.getPositiveValue().intValue() + "\n":"\n");
	}

	/**
	 * The definition of ChipAuthenticationInfo is
     * <pre>
     * ChipAuthenticationInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(
	 *					id-id_CA-DH-3DES-CBC-CBC |
	 *					id-id_CA-DH-AES-CBC-CMAC-128 |
	 *					id-id_CA-DH-AES-CBC-CMAC-192 |
	 *					id-id_CA-DH-AES-CBC-CMAC-256 |
	 *					id-id_CA-ECDH-3DES-CBC-CBC |
	 *					id-id_CA-ECDH-AES-CBC-CMAC-128 |
	 *					id-id_CA-ECDH-AES-CBC-CMAC-192 |
	 *					id-id_CA-ECDH-AES-CBC-CMAC-256),
     *      version		INTEGER, -- MUST be 1 or 2
     *      keyID		INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version); 
		if (keyId!=null) v.add(keyId);
		
		return ASN1Sequence.getInstance(v);
	}

}

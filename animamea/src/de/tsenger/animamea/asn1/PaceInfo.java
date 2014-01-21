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
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 */
public class PaceInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private ASN1Integer version = null;
	private ASN1Integer parameterId = null;
	
	public PaceInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		version = (ASN1Integer) seq.getObjectAt(1);

		if (seq.size() > 2) {
			parameterId = (ASN1Integer) seq.getObjectAt(2);
		}
	}
	
	public PaceInfo(String oid, int version, int parameterId) {
		this.protocol = new ASN1ObjectIdentifier(oid);
		this.version = new ASN1Integer(version);
		this.parameterId = new ASN1Integer(parameterId);
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public Integer getParameterId() {
		if (parameterId == null)
			return null;// ID nicht vorhanden
		else
			return parameterId.getValue().intValue();
	}

	@Override
	public String toString() {
		return "PaceInfo\n\tOID: " + getProtocolOID() + "\n\tVersion: "
				+ getVersion() + 
				(parameterId!=null?"\n\tParameterId: " + getParameterId() + "\n":"\n");
	}

	/**
	 * The definition of PaceInfo is
     * <pre>
     * PaceInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(
	 *					id-PACE-DH-GM-3DES-CBC-CBC |
	 *					id-PACE-DH-GM-AES-CBC-CMAC-128 |
	 *					id-PACE-DH-GM-AES-CBC-CMAC-192 |
	 *					id-PACE-DH-GM-AES-CBC-CMAC-256 |
	 *					id-PACE-ECDH-GM-3DES-CBC-CBC |
	 *					id-PACE-ECDH-GM-AES-CBC-CMAC-128 |
	 *					id-PACE-ECDH-GM-AES-CBC-CMAC-192 |
	 *					id-PACE-ECDH-GM-AES-CBC-CMAC-256,
	 *					id-PACE-DH-IM-3DES-CBC-CBC |
	 *					id-PACE-DH-IM-AES-CBC-CMAC-128 |
	 *					id-PACE-DH-IM-AES-CBC-CMAC-192 |
	 *					id-PACE-DH-IM-AES-CBC-CMAC-256 |
	 *					id-PACE-ECDH-IM-3DES-CBC-CBC |
	 *					id-PACE-ECDH-IM-AES-CBC-CMAC-128 |
	 *					id-PACE-ECDH-IM-AES-CBC-CMAC-192 |
	 *					id-PACE-ECDH-IM-AES-CBC-CMAC-256),
     *      version		INTEGER, -- SHOULD be 2
     *      parameterId	INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version); 
		if (parameterId!=null) v.add(parameterId);
		
		return ASN1Sequence.getInstance(v);
	}
}

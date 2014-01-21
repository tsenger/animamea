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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class PrivilegedTerminalInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private SecurityInfos secinfos = null;

	public PrivilegedTerminalInfo(ASN1Sequence seq) throws IOException {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);

		ASN1Set ASN1Set = (ASN1Set) seq.getObjectAt(1);

		SecurityInfos si = new SecurityInfos();
		si.decode(ASN1Set.getEncoded());

		secinfos = (si);
	}

	public String getProtocolOID() {
		return protocol.getId();
	}

	public SecurityInfos getSecurityInfos() {
		return secinfos;
	}

	@Override
	public String toString() {
		return "PrivilegedTerminalInfo\n\tOID: " + getProtocolOID()
				+ "\n\tSecurityInfos: " + getSecurityInfos() + "\n";
	}

	/**
	 * The definition of PrivilegedTerminalInfo is
     * <pre>
     * PrivilegedTerminalInfo ::= SEQUENCE {
     *      protocol				OBJECT IDENTIFIER(id-PT),
     *      privilegedTerminalInfos	SecurityInfos
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(secinfos);
		
		return ASN1Sequence.getInstance(v);
	}

}

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
public class TerminalAuthenticationInfo extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private ASN1Integer version = null;
	private ASN1Sequence fileID = null;

	/**
	 * @param ASN1Sequence
	 */
	public TerminalAuthenticationInfo(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		version = (ASN1Integer) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (ASN1Sequence) seq.getObjectAt(2);
		}
		if (version.getValue().intValue() == 2 && fileID != null)
			throw new IllegalArgumentException("FileID MUST NOT be used for version 2!");
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public FileID getEFCVCA() {
		if (fileID == null)
			return null; // optionales Feld FileID nicht vorhanden.
		else
			return new FileID(fileID);
	}

	
	@Override
	public String toString() {
		return "TerminalAuthenticationInfo\n\tOID: " + getProtocolOID()
				+ "\n\tVersion: " + getVersion() + 
				(fileID!=null?"\n\tEF.CVCA: " + getEFCVCA() + "\n":"\n");
	}

	/**
	 * The definition of TerminalAuthenticationInfo is
     * <pre>
     * TerminalAuthenticationInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(id-id_TA),
     *      version		INTEGER, -- MUST be 1 or 2
     *      efCVCA		FileID OPTIONAL -- MUST NOT be used for version 2
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version);
		if (fileID!=null) v.add(fileID);
		
		return ASN1Sequence.getInstance(v);
	}

}

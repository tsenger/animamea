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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;

;

/**
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 */
public class CardInfoLocator extends ASN1Object{

	private ASN1ObjectIdentifier protocol = null;
	private DERIA5String url = null;
	private ASN1Sequence fileID = null;

	public CardInfoLocator(ASN1Sequence seq) {
		protocol = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		url = (DERIA5String) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (ASN1Sequence) seq.getObjectAt(2);
		}
	}

	public ASN1ObjectIdentifier getProtocol() {
		return protocol;
	}

	public String getUrl() {
		return url.getString();
	}

	public FileID getFileID() {
		if (fileID == null)
			return null;
		else
			return new FileID(fileID);
	}

	@Override
	public String toString() {
		return "CardInfoLocator \n\tOID: " + getProtocol() + "\n\tURL: " + getUrl()+
				(fileID!=null?"\n\tFileId: " + getFileID() + "\n":"\n");

	}

	/**
	 * The definition of CardInfoLocator is
     * <pre>
     * CardInfoLocator ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(id-CI),
     *      url			IA5String,
     *      efCardInfo	FileID OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(url);
		if (fileID!=null) v.add(fileID);
		return ASN1Sequence.getInstance(v);
	}

}

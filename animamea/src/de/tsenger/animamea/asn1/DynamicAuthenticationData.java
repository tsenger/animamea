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
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * De-/Kodiert die ASN1-Strukturen die für PACE und CA (General Authenticate) benötigt
 * werden.
 * 
 * @author Tobias Senger
 * 
 */
public class DynamicAuthenticationData extends ASN1Object{
	
	private final List<DERTaggedObject> objects = new ArrayList<DERTaggedObject>(3);

	
	/**
	 * Constructor for encoding
	 */
	public DynamicAuthenticationData() {
	}
	
	
	/**
	 * Constructor for decoding
	 * @param data
	 */
	public DynamicAuthenticationData(byte[] data) {

		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;
		
		try {
			das = (DERApplicationSpecific) DERApplicationSpecific.fromByteArray(data);
			seq = ASN1Sequence.getInstance(das.getObject(BERTags.SEQUENCE));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		for (int i = 0; i < seq.size(); i++) {
			DERTaggedObject temp = (DERTaggedObject) seq.getObjectAt(i);
			objects.add(temp);
		}

	}
	
	/**
	 * Fügt ein Tagged Object mit dem Tag (0x80 & tagno) ein.
	 * @param tagno
	 * @param data
	 */
	public void addDataObject(int tagno, byte[] data) {
		objects.add(new DERTaggedObject(false, tagno, new DEROctetString(data)));
	}
	
	/**
	 * Liefert den Inhalt des Tagged Objects mit dem Tag (0x80 & tagno) zurück.
	 * @param tagno
	 * @return
	 */
	public byte[] getDataObject(int tagno) {
		for (DERTaggedObject item : objects) {
			if (item.getTagNo() == tagno) {
				DEROctetString ostr = (DEROctetString) item.getObjectParser(BERTags.OCTET_STRING, false);
				return ostr.getOctets();
			}
		}
		return null;
	}


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector asn1vec = new ASN1EncodableVector();
		
		for (DERTaggedObject item : objects) {
			asn1vec.add(item);
		}

		return new DERApplicationSpecific(0x1C, asn1vec); // Application specific + 0x1c = 0x7C
	}
}

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

package de.tsenger.animamea.iso7816;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Data Object mit dem Tag 97 beeinhaltet die "length expected"-Bytes der ungeschützen CAPDU
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DO97 {

	private byte[] data = null;;
	private DERTaggedObject to = null;

	public DO97() {
	}

	public DO97(byte[] le) {
		data = le.clone();
		to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
	}

	public DO97(int le) {
		data = new byte[1];
		data[0] = (byte) le;
		to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
		;
	}

	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			to = (DERTaggedObject) asn1in.readObject();
			asn1in.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		DEROctetString ocs = (DEROctetString) to.getObject();
		data = ocs.getOctets();

	}

	public byte[] getEncoded() {
		try {
			return to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public byte[] getData() {
		return data;
	}

}

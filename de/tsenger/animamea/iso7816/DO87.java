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

public class DO87 {

	private byte[] value_ = null;
	private byte[] data = null;
	private DERTaggedObject to = null;

	public DO87() {
	}

	public DO87(byte[] data) {
		this.data = data.clone();
		value_ = addOne(data);
		to = new DERTaggedObject(false, 7, new DEROctetString(value_));
	}

	private byte[] addOne(byte[] data) {
		byte[] ret = new byte[data.length + 1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
	}

	private byte[] removeOne(byte[] value) {
		byte[] ret = new byte[value.length - 1];
		System.arraycopy(value, 1, ret, 0, ret.length);
		return ret;
	}

	public void fromByteArray(byte[] encodedData) {
		ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			to = (DERTaggedObject) asn1in.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		DEROctetString ocs = (DEROctetString) to.getObject();
		value_ = ocs.getOctets();
		data = removeOne(value_);
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

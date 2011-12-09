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
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;

public class CertificateHolderAuthorizationTemplate {

	private DERObjectIdentifier terminalType = null;
	private DiscretionaryData auth = null;
	private DERApplicationSpecific chat = null;
	private final byte role;
	
	public CertificateHolderAuthorizationTemplate(DERObjectIdentifier terminalType,
			DiscretionaryData disData) {
		this.terminalType = terminalType;
		this.auth = disData;

		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(terminalType);
		v.add(auth.toASN1Object());

		this.chat = null;
		this.chat = new DERApplicationSpecific(0x4c, v);

		role = (byte) (auth.getData()[0] & 0xc0); 
	}


	public DERObject toASN1Object() {
		return chat;
	}

	public byte[] getEncoded() throws IOException {
		return chat.getEncoded();
	}
	
	public byte getRole(){
	   return role;
	}


}

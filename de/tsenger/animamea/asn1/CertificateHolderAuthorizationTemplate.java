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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTags;

public class CertificateHolderAuthorizationTemplate extends ASN1Encodable{

	private DERObjectIdentifier terminalType = null;
	private DiscretionaryData auth = null;
	private byte role;
	
	public CertificateHolderAuthorizationTemplate(DERObjectIdentifier terminalType,
			DiscretionaryData disData) {
		this.terminalType = terminalType;
		this.auth = disData;		 
	}
	
	public CertificateHolderAuthorizationTemplate(DERSequence chatSeq) throws IOException {
		this.terminalType = (DERObjectIdentifier) chatSeq.getObjectAt(0);
		
		DEROctetString oct = (DEROctetString) ((DERApplicationSpecific) chatSeq.getObjectAt(1)).getObject(DERTags.OCTET_STRING);
		this.auth = new DiscretionaryData(oct.getOctets());
		
	}


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public DERApplicationSpecific toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(terminalType);
		v.add(auth);
 
		return new DERApplicationSpecific(0x4c, v);
	}
	
	public byte getRole(){
		this.role = (byte) (auth.getData()[0] & 0xc0);
		return role;
	}


}

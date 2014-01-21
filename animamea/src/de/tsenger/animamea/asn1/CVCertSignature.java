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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CVCertSignature extends ASN1Object{
	
	DERApplicationSpecific cvcsig = null;
	
	public CVCertSignature(byte[] signatureContent) {
		cvcsig = new DERApplicationSpecific(0x37, signatureContent);
	}
	
	public CVCertSignature(DERApplicationSpecific derApp) throws IllegalArgumentException {
		if (derApp.getApplicationTag()!=0x37) throw new IllegalArgumentException("Contains no Signature with tag 0x5F37");
	else cvcsig = derApp;
	}
	


	@Override
	public byte[] getEncoded(String encoding) throws IOException {
		return cvcsig.getEncoded(ASN1Encoding.DER);
	}
	
	public byte[] getSignature() {
		return cvcsig.getContents();
	}


	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		return cvcsig;
	}

}

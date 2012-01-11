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
import java.util.Date;

import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTags;

import de.tsenger.animamea.tools.Converter;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CVCertBody {
	
	private DERApplicationSpecific cvcbody = null;
	
	private DERInteger profileIdentifier = null;
	private DERIA5String authorityReference = null;	
	private PublicKey publicKey = null;
	private DERIA5String chr = null;
	private CertificateHolderAuthorizationTemplate chat = null;
	private DEROctetString effectiveDate = null;
	private DEROctetString expirationeDate = null;
	private DERSequence extensions = null;
	
	
	public CVCertBody(DERSequence derSeq) {
		
	}
	
	public CVCertBody(DERApplicationSpecific derApp) throws IllegalArgumentException, IOException {
		if (derApp.getApplicationTag()!=0x4E) throw new IllegalArgumentException("contains no Certifcate Body with tag 0x7F4E");
		else cvcbody = derApp;
		
		DERSequence bodySeq= (DERSequence)cvcbody.getObject(DERTags.SEQUENCE);
		profileIdentifier = (DERInteger) ((DERApplicationSpecific) bodySeq.getObjectAt(0)).getObject(DERTags.INTEGER);
		authorityReference = (DERIA5String) ((DERApplicationSpecific) bodySeq.getObjectAt(1)).getObject(DERTags.IA5_STRING);
		
		DERSequence pkSeq = (DERSequence) ((DERApplicationSpecific) bodySeq.getObjectAt(2)).getObject(DERTags.SEQUENCE);
		DERObjectIdentifier pkOid = (DERObjectIdentifier) pkSeq.getObjectAt(0);
		if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.2")) {
			publicKey = new AmECPublicKey(pkSeq); 
		}
		else if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.1")) {
			publicKey = new AmRSAPublicKey(pkSeq);
		}
		
		chr = (DERIA5String) ((DERApplicationSpecific) bodySeq.getObjectAt(3)).getObject(DERTags.IA5_STRING);
		
		DERSequence chatSeq = (DERSequence) ((DERApplicationSpecific) bodySeq.getObjectAt(4)).getObject(DERTags.SEQUENCE);
		chat = new CertificateHolderAuthorizationTemplate(chatSeq);
		
		effectiveDate = (DEROctetString) ((DERApplicationSpecific) bodySeq.getObjectAt(5)).getObject(DERTags.OCTET_STRING);
		
		expirationeDate = (DEROctetString) ((DERApplicationSpecific) bodySeq.getObjectAt(6)).getObject(DERTags.OCTET_STRING);
		
		if (bodySeq.size()>7) {
			extensions = (DERSequence) ((DERApplicationSpecific) bodySeq.getObjectAt(7)).getObject(DERTags.SEQUENCE);
		}
	}
	
	public byte[] getDEREncoded() {
		return cvcbody.getDEREncoded();
	}
	
	public int getProfileIdentifier() {
		return profileIdentifier.getPositiveValue().intValue();
	}
	
	public String getCAR() {
		return authorityReference.getString();
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	public String getCHR() {
		return chr.getString();
	}
	
	public CertificateHolderAuthorizationTemplate getCHAT() {
		return chat;
	}
	
	public Date getEffectiveDateDate() {
		return Converter.BCDtoDate(effectiveDate.getOctets());
	}
	
	public Date getExpirationDate() {
		return Converter.BCDtoDate(expirationeDate.getOctets());
	}
	
	@Override
	public String toString() {
		return new String("Certificate Body\n" +
				"\tProfile Identifier: "+profileIdentifier+"\n" +
				"\tAuthority Reference: "+authorityReference.getString()+"\n" +
				"\tPublic Key: "+publicKey.getOID()+"\n" +
				"\tHolder Reference: "+chr.getString()+"\n" +
				"\tCHAT (Role): "+ chat.getRole()+"\n" +
				"\teffective Date: "+getEffectiveDateDate()+"\n" +
				"\texpiration Date: "+getExpirationDate());		
	}

}

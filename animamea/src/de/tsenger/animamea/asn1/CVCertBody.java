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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;

import de.tsenger.animamea.tools.Converter;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CVCertBody extends ASN1Object{
	
	private DERApplicationSpecific cvcbody = null;
	
	private ASN1Integer profileIdentifier = null;
	private DERIA5String authorityReference = null;	
	private AmPublicKey publicKey = null;
	private DERIA5String chr = null;
	private CertificateHolderAuthorizationTemplate chat = null;
	private DEROctetString effectiveDate = null;
	private DEROctetString expirationDate = null;
	private ASN1Sequence extensions = null;
	
	
	public CVCertBody(ASN1Sequence derSeq) {
		
	}
	
	public CVCertBody(DERApplicationSpecific derApp) throws IllegalArgumentException, IOException {
		if (derApp.getApplicationTag()!=0x4E) throw new IllegalArgumentException("contains no Certifcate Body with tag 0x7F4E");
		else cvcbody = derApp;
		
		ASN1Sequence bodySeq= (ASN1Sequence)cvcbody.getObject(BERTags.SEQUENCE);
		profileIdentifier = (ASN1Integer) ((DERApplicationSpecific) bodySeq.getObjectAt(0)).getObject(BERTags.INTEGER);
		authorityReference = (DERIA5String) ((DERApplicationSpecific) bodySeq.getObjectAt(1)).getObject(BERTags.IA5_STRING);
		
		ASN1Sequence pkSeq = (ASN1Sequence) ((DERApplicationSpecific) bodySeq.getObjectAt(2)).getObject(BERTags.SEQUENCE);
		ASN1ObjectIdentifier pkOid = (ASN1ObjectIdentifier) pkSeq.getObjectAt(0);
		if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.2")) {
			publicKey = new AmECPublicKey(pkSeq); 
		}
		else if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.1")) {
			publicKey = new AmRSAPublicKey(pkSeq);
		}
		
		chr = (DERIA5String) ((DERApplicationSpecific) bodySeq.getObjectAt(3)).getObject(BERTags.IA5_STRING);
		
		ASN1Sequence chatSeq = (ASN1Sequence) ((DERApplicationSpecific) bodySeq.getObjectAt(4)).getObject(BERTags.SEQUENCE);
		chat = new CertificateHolderAuthorizationTemplate(chatSeq);
		
		effectiveDate = (DEROctetString) ((DERApplicationSpecific) bodySeq.getObjectAt(5)).getObject(BERTags.OCTET_STRING);
		
		expirationDate = (DEROctetString) ((DERApplicationSpecific) bodySeq.getObjectAt(6)).getObject(BERTags.OCTET_STRING);
		
		if (bodySeq.size()>7) {
			extensions = (ASN1Sequence) ((DERApplicationSpecific) bodySeq.getObjectAt(7)).getObject(BERTags.SEQUENCE);
		}
	}
	
	@Override
	public byte[] getEncoded(String encoding) throws IOException {
		return cvcbody.getEncoded(encoding);
	}
	
	public int getProfileIdentifier() {
		return profileIdentifier.getPositiveValue().intValue();
	}
	
	public String getCAR() {
		return authorityReference.getString();
	}
	
	public AmPublicKey getPublicKey() {
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
		return Converter.BCDtoDate(expirationDate.getOctets());
	}
	
	public CVExtensions getExtensions() {
		CVExtensions ext = null;
		try {
			ext = CVExtensions.getInstance(extensions);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ext;
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

	/**
	 * CVCertBody contains:
	 * - Certificate Profile Identifier
	 * - Certificate Authority Reference
	 * - Public Key
	 * - Certificate Holder Reference
	 * - Certificate Holder Authorization Template
	 * - Certificate Effective Date
	 * - Certificate Expiration Date
	 * - Certificate Extensions (OPTIONAL)
	 * 
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		try {
			v.add(new DERApplicationSpecific(0x29, profileIdentifier));
			v.add(new DERApplicationSpecific(0x02, authorityReference));
			v.add(publicKey);
			v.add(new DERApplicationSpecific(0x20, chr));
			v.add(chat);
			v.add(new DERApplicationSpecific(0x25, effectiveDate));
			v.add(new DERApplicationSpecific(0x24, expirationDate));
			if (extensions!=null) v.add(new DERApplicationSpecific(0x05, extensions));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        return new DERApplicationSpecific(0x4E, v);
	}

}

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
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmRSAPublicKey extends AmPublicKey implements RSAPublicKey{

	private static final long serialVersionUID = -7184069684377504157L;
	
	private final String algorithm = "RSA";
	private final String format = "CVC";
	
	private DERTaggedObject n = null;
	private DERTaggedObject e = null;

	/**
	 * @param seq
	 */
	public AmRSAPublicKey(ASN1Sequence seq) {
		super(seq);
		decode(seq);
	}
	
	public AmRSAPublicKey(String oidString, BigInteger n, BigInteger e) {
		super(oidString);
		this.n = new DERTaggedObject(false, 1, new ASN1Integer(n));
		this.e = new DERTaggedObject(false, 2, new ASN1Integer(e));
		vec.add(this.n);
		vec.add(this.e);
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		vec.add(this.n);
		vec.add(this.e);
		try {
			return super.getEncoded(ASN1Encoding.DER);
		} catch (IOException e1) {
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return format;
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.asn1.AmPublicKey#decode(org.bouncycastle.asn1.ASN1Sequence)
	 */
	@Override
	protected void decode(ASN1Sequence seq) {
		for (int i = 1; i<seq.size(); i++) {
			DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
			switch(to.getTagNo()) {
			case 1: n = to; break;
			case 2: e = to; break;
			}
		}

	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAKey#getModulus()
	 */
	@Override
	public BigInteger getModulus() {
		if (n==null) return null;
		ASN1Integer derInt;
		derInt = (ASN1Integer) n.getObjectParser(BERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}

	/* (non-Javadoc)
	 * @see java.security.interfaces.RSAPublicKey#getPublicExponent()
	 */
	@Override
	public BigInteger getPublicExponent() {
		if (e==null) return null;
		ASN1Integer derInt;
		derInt = (ASN1Integer) e.getObjectParser(BERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}

}

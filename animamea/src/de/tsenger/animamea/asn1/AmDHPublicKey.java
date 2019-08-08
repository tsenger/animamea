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

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmDHPublicKey extends AmPublicKey implements DHPublicKey{
	
	private static final long serialVersionUID = 5691151250780854614L;

	private final String algorithm = "DH";
	private final String format = "CVC";
	
	private DERTaggedObject p = null;
	private DERTaggedObject g = null;
	private DERTaggedObject q = null;
	private DERTaggedObject y = null;

	/**
	 * @param seq
	 */
	public AmDHPublicKey(ASN1Sequence seq) {
		super(seq);
		decode(seq);
	}
	
	public AmDHPublicKey(String oidString, BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
		super(oidString);
		this.p = new DERTaggedObject(false, 1, new ASN1Integer(p));
		this.q = new DERTaggedObject(false, 2, new ASN1Integer(q));
		this.g = new DERTaggedObject(false, 3, new ASN1Integer(g));
		this.y = new DERTaggedObject(false, 4, new ASN1Integer(y));
		vec.add(this.p);
		vec.add(this.q);
		vec.add(this.g);
		vec.add(this.y);
	}
	
	/**
	 * Konstruktor für Ephemeral Public Key (TR-03110 V2.05 D.3.4)
	 * @param oidString OID
	 * @param y public value
	 */
	public AmDHPublicKey(String oidString, BigInteger y) {
		super(oidString);
		this.y = new DERTaggedObject(false, 4, new ASN1Integer(y));
		vec.add(this.y);
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return format;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		try {
			return super.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.asn1.AmPublicKey#decode(org.bouncycastle.asn1.DERSequence)
	 */
	@Override
	protected void decode(ASN1Sequence seq) {
		for (int i = 1; i<seq.size(); i++) {
			DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
			switch(to.getTagNo()) {
			case 1: p  = to; break;
			case 2: q = to; break;
			case 3: g = to; break;
			case 4: y = to; break;
			}
		}	

	}
	
	/** Returns prime modulus p
	 * @return
	 */
	public BigInteger getP() {
		if (p==null) return null;
		ASN1Integer derInt = null;
		derInt = (ASN1Integer) p.getObjectParser(BERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}
	
	/** Returns generator g
	 * @return
	 */
	public BigInteger getG() {
		if (g==null) return null;
		ASN1Integer derInt = null;
		derInt = (ASN1Integer) g.getObjectParser(BERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}
	
	/** Returns oder of the subgroup q
	 * @return
	 */
	public BigInteger getQ() {
		if (q==null) return null;
		ASN1Integer derInt = null;
		derInt = (ASN1Integer) q.getObjectParser(BERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}

	/* (non-Javadoc)
	 * @see javax.crypto.interfaces.DHPublicKey#getY()
	 */
	@Override
	public BigInteger getY() {
		if (y==null) return null;
		ASN1Integer derInt = null;
		derInt = (ASN1Integer) y.getObjectParser(BERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}

	/* (non-Javadoc)
	 * @see javax.crypto.interfaces.DHKey#getParams()
	 */
	@Override
	public DHParameterSpec getParams() {
		DHParameterSpec dhSpec = new DHParameterSpec(getP(), getG());
		return dhSpec;
	}

}

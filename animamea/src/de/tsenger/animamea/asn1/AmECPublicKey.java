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

import static de.tsenger.animamea.tools.Converter.byteArrayToECPoint;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Klasse für Public Key Data Objects 
 * nach BSI TR-03110 V2.05 Kapitel D.3.3.
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */

public class AmECPublicKey extends AmPublicKey implements ECPublicKey{
	
	private static final long serialVersionUID = 3574151885727849955L;
	
	private final String algorithm = "EC";
	private final String format = "CVC";
	
	private DERTaggedObject p = null;
	private DERTaggedObject a = null;
	private DERTaggedObject b = null;
	private DERTaggedObject G = null;
	private DERTaggedObject r = null;
	private DERTaggedObject Y = null;
	private DERTaggedObject f = null;
	
	/**
	 * Konstruktor zum Dekodieren der übergebenen Sequenz
	 * @param seq
	 */
	public AmECPublicKey(ASN1Sequence seq) {
		super(seq);
		decode(seq);
	}
	
	public AmECPublicKey(String oidString, BigInteger p, BigInteger a, BigInteger b, ECPoint G, BigInteger r, ECPoint Y, BigInteger f ) {
		super(oidString);
		this.p = new DERTaggedObject(false, 1, new ASN1Integer(p));
		this.a = new DERTaggedObject(false, 2, new ASN1Integer(a));
		this.b = new DERTaggedObject(false, 3, new ASN1Integer(b));
		this.G = new DERTaggedObject(false, 4, new DEROctetString(G.getEncoded(false)));
		this.r = new DERTaggedObject(false, 5, new ASN1Integer(r));
		this.Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded(false)));
		this.f = new DERTaggedObject(false, 7, new ASN1Integer(f));
		vec.add(this.p);
		vec.add(this.a);
		vec.add(this.b);
		vec.add(this.G);
		vec.add(this.r);
		vec.add(this.Y);
		vec.add(this.f);
	}
	
	
	/**
	 * Konstruktor für Ephemeral Public Keys (TR-03110 V2.05 D.3.4)
	 * @param oidString OID String
	 * @param Y public point
	 */
	public AmECPublicKey(String oidString, ECPoint Y) {
		super(oidString);
		this.Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded(false)));
		vec.add(this.Y);
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
	
	
	/** Returns prime modulus p
	 * @return
	 */
	public BigInteger getP() {
		if (p==null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(p, false);
		return derInt.getPositiveValue();
	}
	
	/** Returns first coefficient a
	 * @return
	 */
	public BigInteger getA() {
		if (a==null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(a, false);
		return derInt.getPositiveValue();
	}
	
	/** Returns second coefficient b
	 * @return
	 */
	public BigInteger getB() {
		if (b==null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(b, false);
		return derInt.getPositiveValue();
	}
	
	/** Returns base point G
	 * @return
	 */
	public byte[] getG() {
		if (G==null) return null;
		DEROctetString ostr = (DEROctetString) DEROctetString.getInstance(G, false);
		return ostr.getOctets();
	}
	
	/** Returns order of the base point r
	 * @return
	 */
	public BigInteger getR() {
		if (r==null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(r, false);
		return derInt.getPositiveValue();
	}
	
	/** Returns public point Y
	 * @return
	 */
	public byte[] getY() {
		if (Y==null) return null;
		DEROctetString ostr = (DEROctetString) DEROctetString.getInstance(Y, false);
		return ostr.getOctets();
	}
	
	/** Returns cofactor f
	 * @return
	 */
	public BigInteger getF() {
		if (f==null) return null;
		ASN1Integer derInt = ASN1Integer.getInstance(f, false);
		return derInt.getPositiveValue();
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
			case 1: p = to; vec.add(p); break;
			case 2: a = to; vec.add(a); break;
			case 3: b = to; vec.add(b); break;
			case 4: G = to; vec.add(G); break;
			case 5: r = to; vec.add(r); break;
			case 6: Y = to; vec.add(Y); break;
			case 7: f = to; vec.add(f); break;
			}
		}		
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.jce.interfaces.ECKey#getParameters()
	 */
	@Override
	public ECParameterSpec getParameters() {
		ECCurve.Fp curve = new ECCurve.Fp(getP(), getA(), getB());
		ECPoint pointG = byteArrayToECPoint(getG(), curve);	
		ECParameterSpec ecParameterSpec = new ECParameterSpec(curve, pointG, getR(), getF());
		return ecParameterSpec;
	}

	/*
	 * Returns der Public Point (namend Y in BSI TR-03110) 
	 *
	 * @see org.bouncycastle.jce.interfaces.ECPublicKey#getQ()
	 */
	@Override
	public org.bouncycastle.math.ec.ECPoint getQ() {
		ECCurve.Fp curve = new ECCurve.Fp(getP(), getA(), getB());
		ECPoint pointY = byteArrayToECPoint(getY(), curve);	
		return pointY;
	}
	
	public static AmECPublicKey getInstance(byte[] bytes) throws IOException {
		DERApplicationSpecific seq = DERApplicationSpecific.getInstance(bytes);
		AmECPublicKey ecPubKey = new AmECPublicKey(ASN1Sequence.getInstance(seq.getObject(16)));
		return ecPubKey;
	}

}

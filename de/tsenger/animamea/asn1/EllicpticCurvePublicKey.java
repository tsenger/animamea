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

import java.math.BigInteger;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class EllicpticCurvePublicKey extends PublicKey implements ECPublicKey{
	
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
	 * 
	 */
	private static final long serialVersionUID = 3574151885727849955L;

	/**TODO Der Konstruktor macht nur Sinn wenn auch Setter-Methoden vorhanden sind.
	 * Ansonsten sind mit diesem Konstruktor nur leer PK erzeugbar.
	 * @param oidString
	 */
	public EllicpticCurvePublicKey(String oidString) {
		super(oidString);
	}
	
	/**
	 * Konstruktor zum Dekodieren der übergebenen Sequenz
	 * @param seq
	 */
	public EllicpticCurvePublicKey(DERSequence seq) {
		super(seq);
		decode(seq);
	}
	
	public EllicpticCurvePublicKey(String oidString, BigInteger p, BigInteger a, BigInteger b, ECPoint G, BigInteger r, ECPoint Y, BigInteger f ) {
		super(oidString);
		this.p = new DERTaggedObject(false, 1, new DERInteger(p));
		this.a = new DERTaggedObject(false, 2, new DERInteger(a));
		this.b = new DERTaggedObject(false, 3, new DERInteger(b));
		this.G = new DERTaggedObject(false, 4, new DEROctetString(G.getEncoded()));
		this.r = new DERTaggedObject(false, 5, new DERInteger(r));
		this.Y = new DERTaggedObject(false, 6, new DEROctetString(Y.getEncoded()));
		this.f = new DERTaggedObject(false, 7, new DERInteger(f));
		vec.add(this.p);
		vec.add(this.a);
		vec.add(this.b);
		vec.add(this.G);
		vec.add(this.r);
		vec.add(this.Y);
		vec.add(this.f);
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
	
	
	public BigInteger getP() {
		if (p==null) return null;
		DERInteger derInt =(DERInteger) p.getObjectParser(DERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}
	
	public BigInteger getA() {
		if (a==null) return null;
		DERInteger derInt =(DERInteger) a.getObjectParser(DERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}
	
	public BigInteger getB() {
		if (b==null) return null;
		DERInteger derInt =(DERInteger) b.getObjectParser(DERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}
	
	public byte[] getG() {
		if (G==null) return null;
		DEROctetString ostr =(DEROctetString) G.getObjectParser(DERTags.OCTET_STRING, false);
		return ostr.getOctets();
	}
	
	public BigInteger getR() {
		if (r==null) return null;
		DERInteger derInt =(DERInteger) r.getObjectParser(DERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}
	
	public byte[] getY() {
		if (Y==null) return null;
		DEROctetString ostr =(DEROctetString) Y.getObjectParser(DERTags.OCTET_STRING, false);
		return ostr.getOctets();
	}
	
	public BigInteger getF() {
		if (f==null) return null;
		DERInteger derInt =(DERInteger) f.getObjectParser(DERTags.INTEGER, false);
		return derInt.getPositiveValue();
	}


	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		vec.add(this.p);
		vec.add(this.a);
		vec.add(this.b);
		vec.add(this.G);
		vec.add(this.r);
		vec.add(this.Y);
		vec.add(this.f);
		return super.getDEREncoded();
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.asn1.PublicKey#decode(org.bouncycastle.asn1.DERSequence)
	 */
	@Override
	protected void decode(DERSequence seq) {
	
		for (int i = 1; i<seq.size(); i++) {
			DERTaggedObject to = (DERTaggedObject) seq.getObjectAt(i);
			switch(to.getTagNo()) {
			case 1: p = to; break;
			case 2: a = to; break;
			case 3: b = to; break;
			case 4: G = to; break;
			case 5: r = to; break;
			case 6: Y = to; break;
			case 7: f = to; break;
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

}

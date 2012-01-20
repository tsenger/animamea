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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

import de.tsenger.animamea.asn1.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.CertificateHolderAuthorizationTemplate;
import de.tsenger.animamea.asn1.DiscretionaryData;

/**
 * Die Klasse MSESetAT dient zur Konstruktions einer "MSE:Set AT"-APDU
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class MSESetAT {

	public static final int setAT_PACE = 1;
	public static final int setAT_CA = 2;
	public static final int setAT_TA = 3;

	public static final int KeyReference_MRZ = 1;
	public static final int KeyReference_CAN = 2;
	public static final int KeyReference_PIN = 3;
	public static final int KeyReference_PUK = 4;

	private final byte CLASS = (byte) 0x00;
	private final byte INS = (byte) 0x22; // Instruction Byte: Message Security
											// Environment
	private byte[] P1P2 = null;
	private byte[] do80CMR = null;
	private byte[] do83KeyReference = null;
	private byte[] do83KeyName = null;
	private byte[] do84PrivateKeyReference = null;
	private byte[] do7F4C_CHAT = null;
	private byte[] do91EphemeralPublicKEy = null;

	public MSESetAT() {}

	/**
	 * Setzt das zu verwendende Authentication Template (PACE, CA oder TA)
	 * 
	 * @param at
	 *            {@link de.tsenger.androsmex.pace.MSECommand.setAT_PACE},
	 *            {@link de.tsenger.androsmex.pace.MSECommand.setAT_CA},
	 *            {@link de.tsenger.androsmex.pace.MSECommand.setAT_TA}
	 */
	public void setAT(int at) {
		if (at == setAT_PACE)
			P1P2 = new byte[] { (byte) 0xC1, (byte) 0xA4 };
		if (at == setAT_CA)
			P1P2 = new byte[] { (byte) 0x41, (byte) 0xA4 };
		if (at == setAT_TA)
			P1P2 = new byte[] { (byte) 0x81, (byte) 0xA4 };
	}

	/**
	 * Setzt die OID des zu verwendenden Protokolls
	 * 
	 * @param protocol
	 *            Das zu verwendende Protokoll
	 */
	public void setProtocol(String protocol) {
		DERObjectIdentifier oid = new DERObjectIdentifier(protocol);
		DERTaggedObject to = new DERTaggedObject(false, 0x00, oid);
		do80CMR = to.getDEREncoded();

	}

	/**
	 * Setzt das Tag 0x83 (Reference of public / secret key) für PACE
	 * 
	 * @param kr
	 *            Referenziert das verwendete Passwort: 1: MRZ 2: CAN 3: PIN 4:
	 *            PUK
	 */
	public void setKeyReference(int kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DERInteger(kr));
		do83KeyReference = to.getDEREncoded();

	}

	/**
	 * Setzt das Tag 0x83 (Reference of public / secret key) für Terminal
	 * Authentication
	 * 
	 * @param kr
	 *            String der den Namen des Public Keys des Terminals beinhaltet
	 *            (ISO 8859-1 kodiert)
	 */
	public void setKeyReference(String kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DEROctetString(kr.getBytes()));
		do83KeyName = to.getDEREncoded();

	}

	/**
	 * Setzt das Tag 0x84 (Reference of a private key / Reference for computing
	 * a session key)
	 * 
	 * @param pkr
	 *            Bei PACE wird der Index der zu verwendenden Domain Parameter
	 *            angegeben Bei CA wird der Index des zu verwendenden Private
	 *            Keys angegeben Bei RI wird der Index des zu verwendenden
	 *            Private Keys angegeben
	 */
	public void setPrivateKeyReference(byte pkr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x04, new DERInteger(pkr));
		do84PrivateKeyReference = to.getDEREncoded();

	}

	public void setAuxiliaryAuthenticatedData() throws Exception {
		// TODO noch zu implementieren, Tag 0x67
		throw new Exception("setAuxiliaryAuthenticationData not yet implemented!");
	}

	/**
	 * Setzt das Tag 0x91 (Ephemeral Public Key). Der PK muss bereits komprimiert 
	 * (siehe comp()-Funktion in TR-03110) sein.
	 * @param pubKey comp(ephemeral PK_PCD) -> TR-03110 A.2.2.3
	 */
	public void setEphemeralPublicKey(byte[] pubKey) {
		DERTaggedObject to = new DERTaggedObject(false, 0x11, new DEROctetString(pubKey));
		do91EphemeralPublicKEy = to.getDEREncoded();
	}

	/**
	 * @param chat
	 * @throws IOException
	 */
	public void setCHAT(CertificateHolderAuthorizationTemplate chat) throws IOException {
		do7F4C_CHAT = chat.getEncoded();
	}

	/**
	 * Konstruiert aus den gesetzten Objekten eine MSE-Command-APDU und liefert
	 * diese als Byte-Array zurück.
	 * @return ByteArray mit MSE:SetAT APDU
	 */
	public byte[] getBytes() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		if (do80CMR != null)
			bos.write(do80CMR, 0, do80CMR.length);
		if (do83KeyReference != null)
			bos.write(do83KeyReference, 0, do83KeyReference.length);
		if (do83KeyName != null)
			bos.write(do83KeyName, 0, do83KeyName.length);
		if (do84PrivateKeyReference != null)
			bos.write(do84PrivateKeyReference, 0, do84PrivateKeyReference.length);
		if (do91EphemeralPublicKEy != null) 
			bos.write(do91EphemeralPublicKEy, 0 , do91EphemeralPublicKEy.length);
		if (do7F4C_CHAT != null)
			bos.write(do7F4C_CHAT, 0, do7F4C_CHAT.length);
		byte[] data = bos.toByteArray();

		bos.reset();
		bos.write(CLASS);
		bos.write(INS);
		bos.write(P1P2, 0, 2);

		bos.write((byte) data.length);
		bos.write(data, 0, data.length);
		return bos.toByteArray();
	}

	/**
	 * Setzt CHAT-Standardwerte (alle Rechte) für für PACE mit AT.
	 * @throws IOException 
	 * 
	 */
	public void setATChat() throws IOException {
		DiscretionaryData disData = null;
		try {
			disData = new DiscretionaryData(new byte[] { (byte) 0x3F,
					(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xF7 });
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(
				BSIObjectIdentifiers.id_AT, disData);
		setCHAT(chat);
	}

	/**
	 * Setzt CHAT-Standardwerte (alle Rechte) für für PACE mit IS.
	 * @throws IOException 
	 * 
	 */
	public void setISChat() throws IOException {
		DiscretionaryData disData = null;
		try {
			disData = new DiscretionaryData((byte) 0x23);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(
				BSIObjectIdentifiers.id_IS, disData);
		setCHAT(chat);
	}

	/**
	 * Setzt CHAT-Standardwerte (alle Rechte) für für PACE mit ST.
	 * @throws IOException 
	 * 
	 */
	public void setSTChat() throws IOException {
		DiscretionaryData disData = null;
		try {
			disData = new DiscretionaryData((byte) 0x03);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(
				BSIObjectIdentifiers.id_ST, disData);
		setCHAT(chat);
	}

}

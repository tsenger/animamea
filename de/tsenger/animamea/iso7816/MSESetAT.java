/**
 * 
 */
package de.tsenger.animamea.iso7816;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

import de.tsenger.animamea.asn1.bc.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.bc.CertificateHolderAuthorizationTemplate;
import de.tsenger.animamea.asn1.bc.DiscretionaryData;

/**
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
	
	private final byte CLASS = (byte)0x00;
	private final byte INS = (byte)0x22; //Instruction Byte: Message Security Environment
	private byte[] P1P2 = null;
	private byte[] do80CMR = null;
	private byte[] do83KeyReference = null;
	private byte[] do83KeyName = null;
	private byte[] do84PrivateKeyReference = null;
	private byte[] do7F4C_CHAT = null;

	public MSESetAT() {
		// TODO Auto-generated constructor stub
	}
	
	/** Setzt das zu verwendende Authentication Template (PACE, CA oder TA)
	 * @param at {@link de.tsenger.androsmex.pace.MSECommand.setAT_PACE}, 
	 * {@link de.tsenger.androsmex.pace.MSECommand.setAT_CA},
	 * {@link de.tsenger.androsmex.pace.MSECommand.setAT_TA} 
	 */
	public void setAT(int at) {
		if (at==setAT_PACE) P1P2 = new byte[] {(byte)0xC1, (byte)0xA4};
		if (at==setAT_CA) P1P2 = new byte[] {(byte)0x41, (byte)0xA4};
		if (at==setAT_TA) P1P2 = new byte[] {(byte)0x81, (byte)0xA4};		
	}
	
	/** Setzt die OID des zu verwendenden Protokolls
	 * @param protocol Das zu verwendende Protokoll
	 */
	public void setProtocol(String protocol) {
		DERObjectIdentifier oid = new DERObjectIdentifier(protocol);
		DERTaggedObject to = new DERTaggedObject(false, 0x00, oid);
		try {
			do80CMR = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	/** Setzt das Tag 0x83 (Reference of public / secret key) für PACE
	 * @param kr Referenziert das verwendete Passwort:
	 * 1: MRZ
	 * 2: CAN
	 * 3: PIN
	 * 4: PUK
	 */
	public void setKeyReference(int kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DERInteger(kr));
		try {
			do83KeyReference = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** Setzt das Tag 0x83 (Reference of public / secret key) für Terminal Authentication
	 * @param kr String der den Namen des Public Keys des Terminals beinhaltet (ISO 8859-1 kodiert)
	 */
	public void setKeyReference(String kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DEROctetString(kr.getBytes()));
		try {
			do83KeyName = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** Setzt das Tag 0x84 (Reference of a private key / Reference for computing a session key)
	 * @param pkr Bei PACE wird der Index der zu verwendenden Domain Parameter angegeben
	 * Bei CA wird der Index des zu verwendenden Private Keys angegeben
	 * Bei RI wird der Index des zu verwendenden Private Keys angegeben
	 */
	public void setPrivateKeyReference(byte pkr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x04, new DERInteger(pkr));
		try {
			do84PrivateKeyReference = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void setAuxiliaryAuthenticatedData() {
		// TODO noch zu implementieren, Tag 0x67
	}
	
	public void setEphemeralPublicKey() {
		// TODO noch zu implementieren, Tag 0x91
	}
	
	public void setCHAT(CertificateHolderAuthorizationTemplate chat) {
		do7F4C_CHAT = chat.getEncoded();
	}
	
	
	/* Konstruiert aus den gesetzten Objekten eine MSE-Command-APDU und liefert diese als Byte-Array zurück.
	 */
	public byte[] getBytes() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(CLASS);
		bos.write(INS);
		bos.write(P1P2,0,2);
		int lc = 0;
		if (do80CMR!=null) lc += do80CMR.length;
		if (do83KeyReference!=null) lc += do83KeyReference.length;
		if (do84PrivateKeyReference!=null) lc += do84PrivateKeyReference.length;
		if (do7F4C_CHAT!=null) lc += do7F4C_CHAT.length;
		
		bos.write((byte) lc);
		bos.write(do80CMR,0,do80CMR.length);
		bos.write(do83KeyReference,0,do83KeyReference.length);
		bos.write(do84PrivateKeyReference,0,do84PrivateKeyReference.length);
		bos.write(do7F4C_CHAT,0,do7F4C_CHAT.length);
		return bos.toByteArray();
	}
	
	/** Setzt CHAT-Standardwerte (alle Rechte) für für PACE mit AT. 
	 * 
	 */
	public void setATChat() {
		DiscretionaryData disData = null;
		try {
			disData = new DiscretionaryData(new byte[] { (byte)0x3F, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xF7 });
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_AT, disData);
		setCHAT(chat);
	}
	
	/** Setzt CHAT-Standardwerte (alle Rechte) für für PACE mit IS. 
	 * 
	 */
	public void setISChat() {
		DiscretionaryData disData = null;
		try {
			disData = new DiscretionaryData((byte)0x23);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_IS, disData);
		setCHAT(chat);
	}
	
	/** Setzt CHAT-Standardwerte (alle Rechte) für für PACE mit ST. 
	 * 
	 */
	public void setSTChat() {
		DiscretionaryData disData = null;
		try {
			disData = new DiscretionaryData((byte)0x03);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_ST, disData);
		setCHAT(chat);
	}

}

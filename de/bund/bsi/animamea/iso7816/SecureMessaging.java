package de.bund.bsi.animamea.iso7816;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import de.bund.bsi.animamea.crypto.AmAESCrypto;
import de.bund.bsi.animamea.crypto.AmCryptoProvider;
import de.bund.bsi.animamea.crypto.AmDESCrypto;
import de.bund.bsi.animamea.tools.HexString;

public class SecureMessaging {

	private byte[] ks_enc = null;
	private byte[] ks_mac = null;
	private long ssc = 0;
	private AmCryptoProvider crypto_enc = null;
	private AmCryptoProvider crypto_mac = null;

	/**
	 * Konstruktor
	 * 
	 * @param ksenc
	 *            Session Key für Verschlüsselung (K_enc)
	 * @param ksmac
	 *            Session Key für Prüfsummenberechnung (K_mac)
	 * @param initssc
	 *            Initialer Wert des Send Sequence Counters
	 * @throws Exception
	 */
	public SecureMessaging(String algorithm, byte[] ksenc, byte[] ksmac, long initialSSC)
			throws Exception {
		
		if (algorithm.equals("AES")) {
			crypto_enc = new AmAESCrypto();
			crypto_mac = new AmAESCrypto();
		} else if (algorithm.equals("DES")) {
			crypto_enc = new AmDESCrypto();
			crypto_mac = new AmDESCrypto();
		} else
			throw new Exception("Not supported Algorithm");
		
		ks_enc = ksenc.clone();
		ks_mac = ksmac.clone();
		
		ssc = initialSSC;

	}


	/**
	 * Erzeugt aus einer Command-APDU ohne Secure Messaging eine Command-APDU
	 * mit Secure Messaging.
	 * 
	 * @param capdu
	 *            Ungeschützte Command-APDU
	 * @return CommandAPDU mit SM
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 * @throws IllegalStateException
	 * @throws ShortBufferException
	 * @throws DataLengthException
	 */
	public CommandAPDU wrap(CommandAPDU capdu) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, IOException,
			DataLengthException, ShortBufferException, IllegalStateException,
			InvalidCipherTextException {

		byte[] header = null;
		byte lc = 0;
		byte[] paddedheader = null;
		DERTaggedObject do97 = null;
		DERTaggedObject do87 = null;
		DERTaggedObject do8E = null;

		ssc++;

		// Mask class byte and pad command header
		header = new byte[4];
		System.arraycopy(capdu.getBytes(), 0, header, 0, 4); // Die ersten 4 Bytes der
													// CAPDU sind der Header
		header[0] = (byte) (header[0] | (byte) 0x0C);
		paddedheader = crypto_enc.addPadding(header);

		// build DO87
		if (getAPDUStructure(capdu) == 3 || getAPDUStructure(capdu) == 4) {
			do87 = buildDO87(capdu.getData().clone());
			lc += do87.getEncoded().length;
		}

		// build DO97
		if (getAPDUStructure(capdu) == 2 || getAPDUStructure(capdu) == 4) {
			do97 = buildDO97(capdu.getNe());
			lc += do97.getEncoded().length;
		}

		// build DO8E
		do8E = buildDO8E(paddedheader, do87, do97);
		lc += do8E.getEncoded().length;

		// construct and return protected APDU
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		bOut.write(header);
		bOut.write(lc);
		if (do87 != null)
			bOut.write(do87.getEncoded());
		if (do97 != null)
			bOut.write(do97.getEncoded());
		bOut.write(do8E.getEncoded());
		bOut.write(0);

		return new CommandAPDU(bOut.toByteArray());
	}

	public ResponseAPDU unwrap(ResponseAPDU rapdu) throws Exception {

		DERTaggedObject do87 = null;
		DERTaggedObject do99 = null;
		DERTaggedObject do8E = null;
		
		ssc++; 

		int pointer = 0;
		byte[] rapduBytes = rapdu.getData();
		byte[] subArray = new byte[rapduBytes.length];

		while (pointer < rapduBytes.length) {
			System.arraycopy(rapduBytes, pointer, subArray, 0,
					rapduBytes.length - pointer);
			ASN1InputStream asn1sp = new ASN1InputStream(subArray);
			byte[] encodedBytes = asn1sp.readObject().getEncoded();
			
			ASN1InputStream asn1in = new ASN1InputStream(encodedBytes);
			
			switch (encodedBytes[0]) {
			case (byte) 0x87:
				do87 = (DERTaggedObject)asn1in.readObject();
				break;
			case (byte) 0x99:
				do99 = (DERTaggedObject)asn1in.readObject();
				break;
			case (byte) 0x8E:
				do8E = (DERTaggedObject)asn1in.readObject();
			}

			pointer += encodedBytes.length;
		}
		
		if (do99==null) throw new Exception("Secure Messaging error"); //DO99 is mandatory and only absent if SM error occurs
		
		//Construct K (SSC||DO87||DO99)
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		if(do87!=null) bout.write(do87.getEncoded());
		bout.write(do99.getEncoded());
		
		crypto_mac.init(ks_mac, ssc);
		byte[] cc = crypto_mac.getMAC(bout.toByteArray());
		
		byte[] do8eData = ((DEROctetString)do8E.getObject()).getOctets();
		
		if (!java.util.Arrays.equals(cc, do8eData)) throw new Exception("Checksum is incorrect!\nCC: "+HexString.bufferToHex(cc)+"\nDO8E: "+HexString.bufferToHex(do8eData));
		
		//Decrypt DO87
		crypto_enc.init(ks_enc, ssc);
		byte[] value = ((DEROctetString)do87.getObject()).getOctets();
		byte[] do87Data = new byte[value.length-1];
		System.arraycopy(value, 1, do87Data, 0, do87Data.length);
		byte[] data = crypto_enc.decrypt(do87Data);
		
		//Build unwrapped RAPDU
		byte[] unwrappedAPDUBytes = new byte[data.length+2];
		System.arraycopy(data, 0, unwrappedAPDUBytes, 0, data.length);
		byte[] do99Data = ((DEROctetString)do99.getObject()).getOctets();
		System.arraycopy(do99Data, 0, unwrappedAPDUBytes, data.length, do99Data.length);
		
		return new ResponseAPDU(unwrappedAPDUBytes);
	}

	// Pad data, encrypt data with KS.ENC and build DO87
	private DERTaggedObject buildDO87(byte[] data) throws DataLengthException,
			ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, IllegalStateException,
			InvalidCipherTextException, IOException {

		crypto_enc.init(ks_enc, ssc);
		byte[] enc_data = crypto_enc.encrypt(data);

		return new DERTaggedObject(false, 7, new DEROctetString(addOne(enc_data)));

	}
	
	private byte[] addOne(byte[] data) {
		byte[] ret = new byte[data.length+1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
	}

	private DERTaggedObject buildDO8E(byte[] paddedHeader, DERTaggedObject do87, DERTaggedObject do97)
			throws IOException, DataLengthException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			IllegalStateException, InvalidCipherTextException {
		
		ByteArrayOutputStream m = new ByteArrayOutputStream();
		
		m.write(paddedHeader);
		if (do87 != null)
			m.write(do87.getEncoded());
		if (do97 != null)
			m.write(do97.getEncoded());
		
		crypto_mac.init(ks_mac, ssc);
		return new DERTaggedObject(false, 0x0E, new DEROctetString(crypto_mac.getMAC(m.toByteArray())));
	}

	private DERTaggedObject buildDO97(int le) {
		return new DERTaggedObject(false, 0x17, new DERInteger(le));
	}

	/**
	 * Bestimmt welchem Case die CAPDU enstpricht. (Siehe ISO/IEC 7816-3 Kapitel
	 * 12.1)
	 * 
	 * @return Strukurtype (1 = CASE1, ...)
	 */
	private byte getAPDUStructure(CommandAPDU capdu) {
		byte[] cardcmd = capdu.getBytes();

		if (cardcmd.length == 4)
			return 1;
		if (cardcmd.length == 5)
			return 2;
		if (cardcmd.length == (5 + cardcmd[4]) && cardcmd[4] != 0)
			return 3;
		if (cardcmd.length == (6 + cardcmd[4]) && cardcmd[4] != 0)
			return 4;
		if (cardcmd.length == 7 && cardcmd[4] == 0)
			return 5;
		if (cardcmd.length == (7 + cardcmd[5] * 256 + cardcmd[6])
				&& cardcmd[4] == 0 && (cardcmd[5] != 0 || cardcmd[6] != 0))
			return 6;
		if (cardcmd.length == (9 + cardcmd[5] * 256 + cardcmd[6])
				&& cardcmd[4] == 0 && (cardcmd[5] != 0 || cardcmd[6] != 0))
			return 7;
		return 0;
	}
}

package de.tsenger.animamea.iso7816;

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
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import de.tsenger.animamea.crypto.AmCryptoProvider;
import de.tsenger.animamea.tools.HexString;

public class SecureMessaging {

	private byte[] ks_enc = null;
	private byte[] ks_mac = null;
	private long ssc = 0;
	private AmCryptoProvider crypto = null;

	/**
	 * Konstruktor
	 * 
	 * @param acp
	 *            AmDESCrypto- oder AmAESCrypto-Instanz
	 * @param ksenc
	 *            Session Key für Verschlüsselung (K_enc)
	 * @param ksmac
	 *            Session Key für Prüfsummenberechnung (K_mac)
	 * @param initssc
	 *            Initialer Wert des Send Sequence Counters
	 * @throws Exception
	 */
	public SecureMessaging(AmCryptoProvider acp, byte[] ksenc, byte[] ksmac, long initialSSC) {
			
		crypto = acp;
				
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
		DO97 do97 = null;
		DO87 do87 = null;
		DO8E do8E = null;

		ssc++;

		// Mask class byte and pad command header
		header = new byte[4];
		System.arraycopy(capdu.getBytes(), 0, header, 0, 4); // Die ersten 4 Bytes der
													// CAPDU sind der Header
		header[0] = (byte) (header[0] | (byte) 0x0C);
		paddedheader = crypto.addPadding(header);

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

		DO87 do87 = null;
		DO99 do99 = null;
		DO8E do8E = null;
		
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
				do87 = new DO87();
				do87.fromByteArray(asn1in.readObject().getEncoded());
				break;
			case (byte) 0x99:
				do99 = new DO99();
				do99.fromByteArray(asn1in.readObject().getEncoded());
				break;
			case (byte) 0x8E:
				do8E = new DO8E();
				do8E.fromByteArray(asn1in.readObject().getEncoded());
			}

			pointer += encodedBytes.length;
		}
		
		if (do99==null) throw new Exception("Secure Messaging error"); //DO99 is mandatory and only absent if SM error occurs
		
		//Construct K (SSC||DO87||DO99)
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		if(do87!=null) bout.write(do87.getEncoded());
		bout.write(do99.getEncoded());
		
		crypto.init(ks_mac, ssc);
		byte[] cc = crypto.getMAC(bout.toByteArray());
		
		byte[] do8eData = do8E.getData();
		
		if (!java.util.Arrays.equals(cc, do8eData)) throw new Exception("Checksum is incorrect!\nCC: "+HexString.bufferToHex(cc)+"\nDO8E: "+HexString.bufferToHex(do8eData));
		
		//Decrypt DO87
		crypto.init(ks_enc, ssc);
		
		byte[] do87Data = do87.getData();
		byte[] data = crypto.decrypt(do87Data);
		
		//Build unwrapped RAPDU
		byte[] unwrappedAPDUBytes = new byte[data.length+2];
		System.arraycopy(data, 0, unwrappedAPDUBytes, 0, data.length);
		byte[] do99Data = do99.getData();
		System.arraycopy(do99Data, 0, unwrappedAPDUBytes, data.length, do99Data.length);
		
		return new ResponseAPDU(unwrappedAPDUBytes);
	}

	// Pad data, encrypt data with KS.ENC and build DO87
	private DO87 buildDO87(byte[] data) throws DataLengthException,
			ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, IllegalStateException,
			InvalidCipherTextException, IOException {

		crypto.init(ks_enc, ssc);
		byte[] enc_data = crypto.encrypt(data);

		return new DO87(enc_data);

	}


	private DO8E buildDO8E(byte[] paddedHeader, DO87 do87, DO97 do97)
			throws IOException, DataLengthException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			IllegalStateException, InvalidCipherTextException {
		
		ByteArrayOutputStream m = new ByteArrayOutputStream();
		
		m.write(paddedHeader);
		if (do87 != null)
			m.write(do87.getEncoded());
		if (do97 != null)
			m.write(do97.getEncoded());
		
		crypto.init(ks_mac, ssc);
		return new DO8E(crypto.getMAC(m.toByteArray()));
	}

	private DO97 buildDO97(int le) {
		return new DO97(le);
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

package de.bund.bsi.animamea.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 * 
 */
public abstract class AmCryptoProvider {

	protected PaddedBufferedBlockCipher encryptCipher = null;
	protected PaddedBufferedBlockCipher decryptCipher = null;

	// Buffer used to transport the bytes from one stream to another
	byte[] buf = new byte[16]; // input buffer
	byte[] obuf = new byte[512]; // output buffer

	public AmCryptoProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public abstract void init(byte[] keyBytes, long ssc);

	public abstract byte[] getMAC(byte[] data);

	public byte[] encrypt(byte[] in) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {
		// Bytes written to out will be encrypted
		// Read in the cleartext bytes from in InputStream and
		// write them encrypted to out OutputStream
		// optionaly put the IV at the beginning of the cipher file
		// out.write(IV, 0, IV.length);

		ByteArrayInputStream bin = new ByteArrayInputStream(in);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = bin.read(buf)) >= 0) {
			// System.out.println(noBytesRead +" bytes read");

			noBytesProcessed = encryptCipher.processBytes(buf, 0, noBytesRead,
					obuf, 0);
			// System.out.println(noBytesProcessed +" bytes processed");
			bout.write(obuf, 0, noBytesProcessed);
		}

		// System.out.println(noBytesRead +" bytes read");
		noBytesProcessed = encryptCipher.doFinal(obuf, 0);

		// System.out.println(noBytesProcessed +" bytes processed");
		bout.write(obuf, 0, noBytesProcessed);

		bout.flush();

		bin.close();
		bout.close();
		return bout.toByteArray();
	}

	public byte[] decrypt(byte[] in) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {
		// Bytes read from in will be decrypted
		// Read in the decrypted bytes from in InputStream and and
		// write them in cleartext to out OutputStream

		// get the IV from the file
		// DO NOT FORGET TO reinit the cipher with the IV
		// in.read(IV,0,IV.length);
		// this.InitCiphers();

		ByteArrayInputStream bin = new ByteArrayInputStream(in);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = bin.read(buf)) >= 0) {
			// System.out.println(noBytesRead +" bytes read");
			noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead,
					obuf, 0);
			// System.out.println(noBytesProcessed +" bytes processed");
			bout.write(obuf, 0, noBytesProcessed);
		}
		// System.out.println(noBytesRead +" bytes read");
		noBytesProcessed = decryptCipher.doFinal(obuf, 0);
		// System.out.println(noBytesProcessed +" bytes processed");
		bout.write(obuf, 0, noBytesProcessed);

		bout.flush();

		bin.close();
		bout.close();
		return bout.toByteArray();
	}

	

	/**
	 * Diese Methode füllt ein Byte-Array mit dem Wert 0x80 und mehreren 0x00
	 * bis die Länge des übergebenen Byte-Array ein Vielfaches von 8 ist. Dies
	 * ist die ISO9797-1 Padding-Methode 2.
	 * 
	 * @param data
	 *            Das Byte-Array welches aufgefüllt werden soll.
	 * @return Das gefüllte Byte-Array.
	 */
	public byte[] addPadding(byte[] data) {

		int i = 0;
		byte[] tempdata = new byte[data.length + 8];

		for (i = 0; i < data.length; i++) {
			tempdata[i] = data[i];
		}

		tempdata[i] = (byte) 0x80;

		for (i = i + 1; ((i) % 8) != 0; i++) {
			tempdata[i] = (byte) 0;
		}

		byte[] filledArray = new byte[i];
		System.arraycopy(tempdata, 0, filledArray, 0, i);
		return filledArray;
	}

	/**
	 * Entfernt aus dem übergebenen Byte-Array das Padding nach ISO9797-1
	 * Padding-Methode 2. Dazu werden aus dem übergebenen Byte-Array von hinten
	 * beginnend Bytes mit dem Wert 0x00 gelöscht, sowie die der Wert 0x80 der
	 * das Padding markiert.
	 * 
	 * @param Byte
	 *            -Array aus dem das Padding entfernt werden soll
	 * @return bereinigtes Byte-Array
	 */
	public byte[] removePadding(byte[] b) {
		byte[] rd = null;
		int i = b.length - 1;
		do {
			i--;
		} while (b[i] == (byte) 0x00);

		if (b[i] == (byte) 0x80) {
			rd = new byte[i];
			System.arraycopy(b, 0, rd, 0, rd.length);
			return rd;
		}
		return b;
	}
}

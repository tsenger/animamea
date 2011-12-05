package de.tsenger.animamea.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public abstract class AmCryptoProvider {

	protected PaddedBufferedBlockCipher encryptCipher = null;
	protected PaddedBufferedBlockCipher decryptCipher = null;

	// Buffer are used to transport the bytes from one stream to another
	byte[] buf = new byte[16]; // input buffer
	byte[] obuf = new byte[512]; // output buffer

	public AmCryptoProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	/**
	 * Initialisiert die Crypto-Engine mit dem angegebenen Schlüssel
	 * und dem Send Sequence Counter (SSC)
	 * 
	 * @param keyBytes
	 *            Schlüssel
	 * @param ssc
	 *            Send Sequence Counter
	 */
	public abstract void init(byte[] keyBytes, byte[] ssc);
	
	public abstract int getBlockSize();
	
	public abstract byte[] decryptBlock(byte[] key, byte[] z);
	
	/**
	 * Berechnet den Mac der übergebenen Daten ohne vorherige Initialisierung (@see #init(byte[], long). 
	 * Es wird daher kein SSC benötigt.
	 * @param key Schlüssel
	 * @param data Die Daten über die der MAC gebildet werden soll.
	 * @return MAC
	 */
	public abstract byte[] getMAC(byte[] key, byte[] data);

	/** 
	 * Berechnet den Message Authentication Code (MAC) aus dem übergebenen ByteArray.
	 * Die Parametern werden vorher mit der Methode @see #init(byte[], long) eingestellt. 
	 * @param data Die Daten über die der MAC gebildet werden soll.
	 * @return MAC
	 */
	public abstract byte[] getMAC(byte[] data);

	/**
	 * Verschlüsselt das übergebene ByteArray mit den Parametern die beim @see #init(byte[], long) eingestellt wurden. 
	 * 
	 * @param in ByteArray mit den zu verschlüsselnden Daten
	 * @return ByteArray mit den entschlüsselten Daten.
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws DataLengthException
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws IOException
	 */
	public byte[] encrypt(byte[] in) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {

		ByteArrayInputStream bin = new ByteArrayInputStream(in);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = bin.read(buf)) >= 0) {
			noBytesProcessed = encryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
			bout.write(obuf, 0, noBytesProcessed);
		}

		noBytesProcessed = encryptCipher.doFinal(obuf, 0);

		bout.write(obuf, 0, noBytesProcessed);

		bout.flush();

		bin.close();
		bout.close();
		return bout.toByteArray();
	}

	/**
	 * Entschlüsselt das übergebene ByteArray mit den Parametern die beim @see #init(byte[], long) eingestellt wurden. 
	 * @param in BytrArray mit den verschlüsselten Daten
	 * @return ByteArray mit den entschlüsselten Daten
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws DataLengthException
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws IOException
	 */
	public byte[] decrypt(byte[] in) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException,
			DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {

		ByteArrayInputStream bin = new ByteArrayInputStream(in);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = bin.read(buf)) >= 0) {
			noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead,obuf, 0);
			bout.write(obuf, 0, noBytesProcessed);
		}
		noBytesProcessed = decryptCipher.doFinal(obuf, 0);
		
		bout.write(obuf, 0, noBytesProcessed);

		bout.flush();

		bin.close();
		bout.close();
		return bout.toByteArray();
	}

	

	/**
	 * Diese Methode füllt ein Byte-Array mit dem Wert 0x80 und mehreren 0x00
	 * bis die Länge des übergebenen Byte-Array ein Vielfaches der Blocklänge ist. Dies
	 * ist die ISO9797-1 Padding-Methode 2 bzw. ISO7816d4-Padding
	 * 
	 * @param data
	 *            Das Byte-Array welches aufgefüllt werden soll.
	 * @return Das gefüllte Byte-Array.
	 */
	public byte[] addPadding(byte[] data) {
		
		int len = data.length;
		int nLen = ((len/getBlockSize())+1)*getBlockSize();
		byte[] n = new byte[nLen];
		System.arraycopy(data, 0, n, 0, data.length);
		new ISO7816d4Padding().addPadding(n, len);
		return n;
	}

	/**
	 * Entfernt aus dem übergebenen Byte-Array das Padding nach ISO9797-1
	 * Padding-Methode 2 bzw. ISO7816d4-Padding. 
	 * 
	 * @param b Byte-Array aus dem das Padding entfernt werden soll
	 * @return Padding-bereinigtes Byte-Array
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

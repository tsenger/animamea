/**
 * 
 */
package de.bund.bsi.animamea.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 * 
 */
public class AmAESCrypto extends AmCryptoProvider {

	PaddedBufferedBlockCipher encryptCipher = null;
	PaddedBufferedBlockCipher decryptCipher = null;

	// Buffer used to transport the bytes from one stream to another
	byte[] buf = new byte[16]; // input buffer
	byte[] obuf = new byte[512]; // output buffer
	// The key
	byte[] key = null;
	// The initialization vector needed by the CBC mode
	byte[] IV = null;

	// The default block size
	public static int blockSize = 16;


	public void initCiphers(byte[] keyBytes, byte[] iv) {

		// get the key
		key = new byte[keyBytes.length];
		System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);

		// get the IV
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);
		
		// create the ciphers
		// AES block cipher in CBC mode with ISO7816d4 padding
		encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding() );

		decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding() );

		// create the IV parameter
		ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(
				key), IV);

		encryptCipher.init(true, parameterIV);
		decryptCipher.init(false, parameterIV);
	}

	@Override
	public void encrypt(InputStream in, OutputStream out)
			throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {
		// Bytes written to out will be encrypted
		// Read in the cleartext bytes from in InputStream and
		// write them encrypted to out OutputStream
		// optionaly put the IV at the beginning of the cipher file
		// out.write(IV, 0, IV.length);

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = in.read(buf)) >= 0) {
			// System.out.println(noBytesRead +" bytes read");

			noBytesProcessed = encryptCipher.processBytes(buf, 0, noBytesRead,
					obuf, 0);
			// System.out.println(noBytesProcessed +" bytes processed");
			out.write(obuf, 0, noBytesProcessed);
		}

		// System.out.println(noBytesRead +" bytes read");
		noBytesProcessed = encryptCipher.doFinal(obuf, 0);

		// System.out.println(noBytesProcessed +" bytes processed");
		out.write(obuf, 0, noBytesProcessed);

		out.flush();

		in.close();
		out.close();
	}

	@Override
	public void decrypt(InputStream in, OutputStream out)
			throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {
		// Bytes read from in will be decrypted
		// Read in the decrypted bytes from in InputStream and and
		// write them in cleartext to out OutputStream

		// get the IV from the file
		// DO NOT FORGET TO reinit the cipher with the IV
		// in.read(IV,0,IV.length);
		// this.InitCiphers();

		int noBytesRead = 0; // number of bytes read from input
		int noBytesProcessed = 0; // number of bytes processed

		while ((noBytesRead = in.read(buf)) >= 0) {
			// System.out.println(noBytesRead +" bytes read");
			noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead,
					obuf, 0);
			// System.out.println(noBytesProcessed +" bytes processed");
			out.write(obuf, 0, noBytesProcessed);
		}
		// System.out.println(noBytesRead +" bytes read");
		noBytesProcessed = decryptCipher.doFinal(obuf, 0);
		// System.out.println(noBytesProcessed +" bytes processed");
		out.write(obuf, 0, noBytesProcessed);

		out.flush();

		in.close();
		out.close();
	}

}

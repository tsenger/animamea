/**
 * 
 */
package de.bund.bsi.animamea.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 * 
 */
public class AmAESCrypto extends AmCryptoProvider {
	
	public AmAESCrypto() {
		Security.addProvider(new BouncyCastleProvider());
	}

	Cipher encryptCipher = null;
	Cipher decryptCipher = null;

	// Buffer used to transport the bytes from one stream to another
	byte[] buf = new byte[16]; // input buffer
	byte[] obuf = new byte[512]; // output buffer
	// The key
	byte[] key = null;
	// The initialization vector needed by the CBC mode
	byte[] IV = null;

	// The default block size
	public static int blockSize = 16;


	public void initCiphers(byte[] keyBytes, byte[] iv) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

		 //1. create the cipher using Bouncy Castle Provider
	       encryptCipher =
	               Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
	       //2. create the key
	       SecretKey keyValue = new SecretKeySpec(keyBytes,"AES");
	       //3. create the IV
	       AlgorithmParameterSpec IVspec = new IvParameterSpec(iv);
	       //4. init the cipher
	       encryptCipher.init(Cipher.ENCRYPT_MODE, keyValue, IVspec);

	       //1 create the cipher
	       decryptCipher =
	               Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
	       //2. the key is already created
	       //3. the IV is already created
	       //4. init the cipher
	       decryptCipher.init(Cipher.DECRYPT_MODE, keyValue, IVspec);
	}

	@Override
	public byte[] encrypt(byte[] in)
			throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, DataLengthException, IllegalStateException,
			InvalidCipherTextException, IOException {
		// Bytes written to out will be encrypted
		// Read in the cleartext bytes from in InputStream and
		// write them encrypted to out OutputStream
		// optionaly put the IV at the beginning of the cipher file
		// out.write(IV, 0, IV.length);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CipherOutputStream cOut = new CipherOutputStream(bOut, encryptCipher);

       
                cOut.write(in);
            
            cOut.close();
     

        return bOut.toByteArray();

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
//			noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead,
//					obuf, 0);
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

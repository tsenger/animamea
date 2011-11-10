/**
 * 
 */
package de.bund.bsi.animamea.iso7816;

import static de.bund.bsi.animamea.iso7816.CardCommands.readBinary;
import static de.bund.bsi.animamea.iso7816.CardCommands.selectEF;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import de.bund.bsi.animamea.AmCardHandler;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 *
 */
public class FileAccess {
	
	AmCardHandler ch = null;
	
	public FileAccess(AmCardHandler cardHandler) {
		ch = cardHandler;	
	}
	
	/**
	 * Reads the content of an elementary transparent file (EF). 
	 * If the file is bigger then 255 byte this function uses multiply 
	 * READ BINARY command to get the whole file.
	 * @param sfid Short File Identififier of the EF to read. Must be between 0x01 and 0x1F.
	 * @return Returns the content of the EF with the given SFID
	 * @throws Exception
	 */
	public byte[] getFile(byte sfid) throws Exception {
		if (sfid>0x1F) throw new Exception("Invalid Short File Identifier!");
		
		ResponseAPDU resp = ch.transceive(readBinary(sfid, (byte)0x08));
		if (resp.getSW1()!=0x90) throw new Exception("Can't read File (SFID: "+sfid+"). SW: "+resp.getSW());
		int fileLength = getLength(resp.getData());
		return readFile(fileLength);
	}
	
	/**
	 * Reads the content of an elementary transparent file (EF). 
	 * If the file is bigger then 255 byte this function uses multiply 
	 * READ BINARY command to get the whole file.
	 * @param fid A 2 byte array which contains the FID of the EF to read.
	 * @return Returns the content of the EF with the given SFID
	 * @throws Exception
	 */
	public byte[] getFile(byte[] fid) throws Exception {
		if (fid.length!=2) throw new Exception("Length of FID must be 2.");
		if ((fid[0]&(byte)0x10)==(byte)0x10) throw new Exception("Bit 8 of P1 must be 0 if READ BINARY with FID is used");
		ResponseAPDU resp = ch.transceive(selectEF(fid));
		resp = ch.transceive(readBinary((byte)0,(byte)0,(byte)0x8));
		int fileLength = getLength(resp.getData());
		return readFile(fileLength);
	}

	/**
	 * @param length Length of the file to read
	 * @return file content
	 * @throws CardException
	 */
	private byte[] readFile(int length) throws CardException {
		int remainingBytes = length;
		ResponseAPDU resp;
		byte[] fileData = new byte[length];
		
		int maxReadLength = 0xFF;	
		int i = 0;
		
        do {
        	int offset = i*maxReadLength;
    		byte off1 = (byte) ((offset & 0x0000FF00) >> 8);
    		byte off2 = (byte) (offset & 0x000000FF);
    		
        	if (remainingBytes <= maxReadLength) {
        		resp = ch.transceive(readBinary(off1, off2, (byte) remainingBytes));
        		remainingBytes = 0;
        	}
        	else {
        		resp = ch.transceive(readBinary(off1, off2, (byte) maxReadLength));
        		remainingBytes -= maxReadLength;
        	}
            System.arraycopy(resp.getData(),0,fileData,i*maxReadLength,resp.getData().length);
            i++;
            
           
        } while (remainingBytes>0);
        return fileData;
	}
		
	
	/**
	 * Get the length value from a TLV coded byte array 
	 * This function is adapted from bouncycastle 
	 * @see org.bouncycastle.asn1.ASN1InputStream#readLength(InputStream s, int limit)
	 * 
	 * @param b TLV coded byte array that contains at least the tag and the length value. The data value is not necessary. 
	 * @return
	 * @throws IOException
	 */
	private int getLength(byte[] b) throws IOException {
		ByteArrayInputStream s = new ByteArrayInputStream(b);
		int size=0;
		s.read(); // Skip the fhe first byte which contains the Tag value
		int length = s.read(); 
		if (length < 0)
			throw new EOFException("EOF found when length expected");

		if (length == 0x80)
			return -1; // indefinite-length encoding

		if (length > 127) {
			size = length & 0x7f;

			// Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be
			// caught here
			if (size > 4)
				throw new IOException("DER length more than 4 bytes: " + size);

			length = 0;
			for (int i = 0; i < size; i++) {
				int next = s.read();
				if (next < 0) 
					throw new EOFException("EOF found reading length");
				length = (length << 8) + next;
			}

			if (length < 0)
				throw new IOException("corrupted stream - negative length found");

		}
		return length+size+2; // +1 Tag, +1 Längenangabe
	}

}

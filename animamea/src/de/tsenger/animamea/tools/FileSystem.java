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
package de.tsenger.animamea.tools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class FileSystem {
	
	
	/**
	 * Get the content of the given file 
	 * 
	 * @param filename path and filename 
	 * @return binary content of the selected file
	 * @throws IOException 
	 */
	public static byte[] readFile(String filename) throws IOException {
		FileInputStream in = null;
		File efCardAccessFile = new File(filename);
		byte buffer[] = new byte[(int) efCardAccessFile.length()	];

		in = new FileInputStream(efCardAccessFile);
		in.read(buffer, 0, buffer.length);
		in.close();

		return buffer;
	}

	
	/**Saves data with the name given in parameter efName into a local file.
    *
    * @param fileName The Name of the file
    * @param data
    * @return Returns 'true' if the record were saved to a local file on hd.
	 * @throws IOException 
    */
	public static boolean saveFile(String fileName, byte[] data) throws IOException {
		boolean success = false;		
		
		File file = new File(fileName);
		FileOutputStream fos;
		fos = new FileOutputStream( file );
		fos.write(data);
		fos.close();
		success = true;
		
		return success;
	} 

}

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
package de.tsenger.sandbox;

import java.io.FileWriter;
import java.io.IOException;
import java.security.PublicKey;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.asn1.SecurityInfos;
import de.tsenger.animamea.iso7816.FileAccess;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.pace.PaceException;
import de.tsenger.animamea.pace.PaceOperator;
import de.tsenger.animamea.statistics.Statistics;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class TimeMeasurement {

	private static Logger logger = Logger.getLogger(TimeMeasurement.class);
	private static AmCardHandler ch = null;
	private static FileAccess facs = null;
	static final byte[] FID_EFCA = new byte[] { (byte) 0x01, (byte) 0x1C };

	private static int slotID = 1;

	public static void main(String[] args) throws Exception {

		PropertyConfigurator.configure("log4j.properties");

		logger.info("Entering application.");

		Statistics stat1 = new Statistics();
		Statistics stat2 = new Statistics();
		Statistics stat3 = new Statistics();
		Statistics stat4 = new Statistics();
		Statistics stat5 = new Statistics();

		connectCard();
		// facs = new FileAccess(ch);
		//
		// SecurityInfos cardAccess = getEFCardAccess();
		// PublicKey ephPacePublicKey = performPACE(cardAccess);

		CommandAPDU mse = new CommandAPDU(HexString.hexToBuffer("00 22 c1 a4 0f 80 0a 04 00 7f 00 07 02 02 04 02 02 83 01 03"));
		CommandAPDU ga1 = new CommandAPDU(HexString.hexToBuffer("10 86 00 00 02 7c 00 ff"));
		CommandAPDU ga2 = new CommandAPDU(HexString.hexToBuffer("10 86 00 00 45 7c 43 81 41 04 59 3d 98 0a 6c 5b"
				+ "d1 40 72 2b 42 2a 4c 29 4a 4a dc 0a da 8f 89 e0" + "19 fa 21 9f 7f 73 d1 2c ae 4c 67 26 c5 ef da e6"
				+ "29 ca 7e ec 2d 76 45 91 2c 7f 7f 59 08 66 f0 94" + "e3 5b d2 a4 f3 da ec 7d fb d2 ff"));
		CommandAPDU ga3 = new CommandAPDU(HexString.hexToBuffer("10 86 00 00 45 7c 43 83 41 04 29 4d d3 0a 21 7d"
				+ "59 a6 b8 2f fb 04 80 80 84 37 ad 3e 46 f6 76 3d" + "70 7b c3 91 26 21 fa 84 5e 80 30 f3 db 2c ab 55"
				+ "33 03 9c 8e 64 2d 9b 5e ed 69 fa 62 40 2d bb c7" + "41 0e 0f f2 c5 94 b3 1d c7 f6 ff"));
		CommandAPDU ga4 = new CommandAPDU(HexString.hexToBuffer("00 86 00 00 0c 7c 0a 85 08 52 ee 19 8d 36 f6 b9" + "a1 ff"));

		ResponseAPDU res;

		for (int i = 0; i < 10000; i++) {

			long start_mse = System.currentTimeMillis();
			res = ch.transceive(mse);
			long mse_ga1 = System.currentTimeMillis();
			res = ch.transceive(ga1);
			long ga1_ga2 = System.currentTimeMillis();
			if (res.getSW() != 0x9000)
				break;
			// ch.transceive(ga2);
			// long ga2_ga3 =System.currentTimeMillis();
			// ch.transceive(ga3);
			// long ga3_ga4 =System.currentTimeMillis();
			// ch.transceive(ga4);
			// long ga4_end =System.currentTimeMillis();
			//
			double t1 = (mse_ga1 - start_mse);
			double t2 = (ga1_ga2 - mse_ga1);
			// double t3 = (ga2_ga3-ga1_ga2);
			// double t4 = (ga3_ga4-ga2_ga3);
			// double t5 = (ga4_end-ga3_ga4);

			stat1.update(t1);
			stat2.update(t2);
			// stat3.update(t3);
			// stat4.update(t4);
			// stat5.update(t5);

			System.out.printf("Testrun: %05d", i + 1);
			// System.out.println("MSE:Set id_AT\n" + t1);
			System.out.printf(", duration: %5.2f%n", (t2 / 1000));

			// System.out.println("Map Nonce\n"+stat3.toString());
			// System.out.println("Key Agreement\n"+stat4.toString());
			// System.out.println("Mutual Authenticate\n"+stat5.toString());
			//
			// String[] data = new String[5];
			// data[0] = Double.toString(t1);
			// data[1] = Double.toString(t2);
			// data[2] = Double.toString(t3);
			// data[3] = Double.toString(t4);
			// data[4] = Double.toString(t5);
			//
			// createCsvFile("measurement.csv", data);
			//

		}

		System.out.println("Statistics for \"MSE Set AT\"\n" + stat1.toString());
		System.out.println("Statistics for \"Get Challenge\"\n" + stat2.toString());

		// ch.transceive(ga2);
		// ch.transceive(ga3);
		// ch.transceive(ga4);
	}

	private static void reconnect() {
		try {
			ch.disconnect();
			ch.connect(slotID);
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static void connectCard() {

		// CardHandler erzeugen und erstes Terminal verbinden
		ch = new AmCardHandler();

		try {
			if (!ch.connect(slotID)) // 0 = First terminal
			{
				logger.error("Can't connect to card!");
				System.exit(0);
			}
		} catch (CardException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	}

	private static SecurityInfos getEFCardAccess() throws CardException {

		SecurityInfos efca = null;
		try {
			byte[] efcaBytes = facs.getFile(FID_EFCA, true);
			efca = new SecurityInfos();
			efca.decode(efcaBytes);
			logger.info("EF.CardAccess decoded");
			logger.debug("\n" + efca);
		} catch (IOException e) {
			logger.error("Couldn't decode EF.CardAccess", e);
		} catch (SecureMessagingException e) {
			logger.error("SecureMessaging failed!", e);
		}
		return efca;
	}

	private static PublicKey performPACE(SecurityInfos cardAccess) throws PaceException, CardException {

		PaceOperator pop = new PaceOperator(ch);
		pop.setAuthTemplate(cardAccess.getPaceInfoList().get(0), "819955", 2, 0);

		// Führe id_PACE durch
		SecureMessaging sm = null;
		try {
			sm = pop.performPace();
		} catch (SecureMessagingException e) {
			throw new PaceException("SecureMessaging failure while performing id_PACE", e);
		}

		// Wenn id_PACE erfolgreich durchgeführt wurde, wird sein
		// SecureMessaging-Objekt
		// mit gültigen Session-Keys zurückgeliefert.
		if (sm != null)
			logger.info("id_PACE established");
		ch.setSecureMessaging(sm);
		return pop.getPKpicc();
	}

	private static void createCsvFile(String sFileName, String[] data) {
		try {
			FileWriter writer = new FileWriter(sFileName, true);

			for (int i = 0; i < data.length; i++) {
				writer.append(data[i]);
				writer.append(',');
			}
			writer.append('\n');

			writer.flush();
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}

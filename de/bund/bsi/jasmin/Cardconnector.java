package de.bund.bsi.jasmin;

import javax.smartcardio.*;

import de.bund.bsi.jasmin.tools.HexString;

public class Cardconnector {

    /**
    *
    * @param index is the array index of the terminal list (0..x)
    * @throws CardException if there are problems accessing the smartcard
     * @throws NoSuchAlgorithmException 
    */
   public static void connectCard(int index) throws CardException{
      
       /* Is a Reader connected we can access? */
       if (TerminalFactory.getDefault().terminals().list().size() == 0) {
           System.err.println("No reader present");
           return;
       }
      
       /* Terminal we are working on */
        CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(index);
      
       /* Is a card present? */
       if (!terminal.isCardPresent()) {
           System.err.println("No Card present!");
           return;
       }
      
       /* Here you have to choose "T=0","T=1", "T=2", check documentation of your smart card */
       //Mostly it's "T=1", for older cards its "T=0"
       Card card = terminal.connect("T=1");
      
       System.out.println("Card_Info: "+card.toString());
       System.out.println("Card Protocol: "+ card.getProtocol());
      
       //Reset the card for use
       ATR atr = card.getATR();

       System.out.println("ATR: " + HexString.bufferToHex(atr.getBytes()));
       System.out.println("ATR historical bytes: "+ HexString.bufferToHex(atr.getHistoricalBytes()));
      
       /* Get the basic channel. This one can't be closed */
       CardChannel channel = card.getBasicChannel();
      
       /* Try to send a command. This one won't work! */
       byte[] command = { (byte)0x00, (byte)0xB0, (byte)0x9C, 0, (byte)0x08};
      
       CommandAPDU someApdu = new CommandAPDU(command);
      
       ResponseAPDU r = channel.transmit(someApdu);
       /* Response encoded in bytes */
       byte[] response = r.getBytes();
      
       System.out.println("response: "+ HexString.bufferToHex(response));
          
       card.disconnect(false);
   }
  
  
   public static void main(String[] args) {
       try {
           //First Terminal = 0
           connectCard(0);
       } catch (Exception e) {
           e.printStackTrace();
       }
   }

	

}

package de.tsenger.sandbox;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

public class Smart
{
  public static void main (String[] args)
    {
      try
        {
          // show the list of available terminals
          TerminalFactory factory = TerminalFactory.getDefault();
          List<CardTerminal>  terminals = factory.terminals().list();
          // get the first terminal
          if (terminals.isEmpty ())
            {
              System.out.println ("No terminals found!");
            }
          else
            {
              System.out.println("Terminals: " + terminals);
              CardTerminal terminal = terminals.get(0);
              // establish a connection with the card
              Card card = terminal.connect("T=0");
              System.out.println("card: " + card);
              CardChannel channel = card.getBasicChannel();
              // disconnect
              card.disconnect(false);
            }
        }
      catch (Exception e)
        {
           e.printStackTrace ();
        }
    }
}
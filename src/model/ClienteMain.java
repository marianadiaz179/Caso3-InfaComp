package model;

import java.io.IOException;
import java.net.Socket;

public class ClienteMain {

    private static Socket ss;	
    private static String host = "localhost";
	private static int puerto = 4030;

	public static void main(String[] args) throws IOException 
    {
        for (int i=0; i<1; i++)
        {
            ss = new Socket(host,puerto);
            System.out.println("Sending new Client with id " + i);

            ClientThread client = new ClientThread(ss, i);
            client.start();
        }
		
    }
}

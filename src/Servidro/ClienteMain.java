package Servidro;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class ClienteMain {

    private static Socket ss;	
    private static String host = "localhost";
	private static final String ID = "Client Server: ";
    private DataOutputStream salida;
    private DataInputStream entrada;
	private static int puerto = 4030;

	public static void main(String[] args) throws IOException 
    {
        for (int i=0; i<1; i++)
        {
            ss = new Socket(host,puerto);
            System.out.println("Sending new Client with id " + i);

            ClientThread client = new ClientThread(ss);
            client.start();
        }
		
    }
}

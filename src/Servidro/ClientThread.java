package Servidro;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;

public class ClientThread extends Thread 
{

    // Atributos
	private Socket sc = null;
	private int id;
	private String dlg;	
	private BigInteger p;
	private BigInteger g;
	private SecurityFunctions f;	
	private int mod;

    ClientThread (Socket csP) {
		sc = csP;
		
	}


    @Override
    public void run() {
        
        boolean exito = true;
		String linea;
	    System.out.println(dlg + "starting.");
	    f = new SecurityFunctions();

	    try {

			//inicializa la llave pública
			PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub",dlg);
			PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
			BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));

			//Avisa al servidor que puede iniciar
			ac.println("SECURE INIT");
			
			//Recibe g,p y g2x
            String g = dc.readLine();
            String p = dc.readLine();
            String g2x = dc.readLine();

			System.out.println("G: " + g);
			System.out.println("P: " + p);
			System.out.println("G2X: " + g2x);

			//Verifica si la firma coincide con los valores de g,p y g2x
            String signature = dc.readLine();
			String mensaje = g + "," + p +"," + g2x;
			//boolean verificacion = f.checkSignature(publicaServidor, signature, mensaje)

			/*if(//signature.compareTo() == 0){
				ac.println("OK");
			}
			else{
				ac.println("ERROR");
			}*/
		
	        sc.close();
	    } catch (Exception e) {
			 e.printStackTrace(); }

	
        
    }    
}

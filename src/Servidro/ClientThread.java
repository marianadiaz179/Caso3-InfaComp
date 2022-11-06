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
            String g1 = dc.readLine();
            String p1 = dc.readLine();
            String g2x = dc.readLine();
			g = new BigInteger(g1);
			p = new BigInteger(p1);

			System.out.println("G: " + g1);
			System.out.println("P: " + p1);
			System.out.println("G2X: " + g2x);

			//Verifica si la firma coincide con los valores de g,p y g2x
            String signature = dc.readLine();
			String mensaje = g + "," + p +"," + g2x;
			byte[] firma = str2byte(signature);
			
			boolean verificacion = f.checkSignature(publicaServidor, firma, mensaje);

			if(verificacion == true){
				ac.println("OK");
			}
			else{
				ac.println("ERROR");
			}

			//Generar G^y
			SecureRandom r = new SecureRandom();
			int y = Math.abs(r.nextInt());
			
    		Long longy = Long.valueOf(y);
    		BigInteger biy = BigInteger.valueOf(longy);
    		BigInteger valor_comun = G2Y(g,biy,p);
    		String str_valor_comun = valor_comun.toString();
    		System.out.println(dlg + "G2Y: "+str_valor_comun);

			//manda G2Y
			ac.println(str_valor_comun);

		
	        sc.close();
	    } catch (Exception e) {
			 e.printStackTrace(); }

	
        
    }  
	
	public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}

	private BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}
}

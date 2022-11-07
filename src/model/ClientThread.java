package model;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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

    ClientThread (Socket csP, int id) {
		sc = csP;
		dlg = new String("Client " + id + ": ");
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

			// 1. Avisa al servidor que puede iniciar
			ac.println("SECURE INIT");
			
			// 2. El servidor genera los parametros para DH(G,P,G2X
			
			// 3. Recibe g,p y g2x
            String str_g = dc.readLine();
            String str_p = dc.readLine();
            String str_g2x = dc.readLine();
			g = new BigInteger(str_g);
			p = new BigInteger(str_p);
			BigInteger g2x = new BigInteger(str_g2x);

			System.out.println("G: " + str_g);
			System.out.println("P: " + str_p);
			System.out.println("G2X: " + str_g2x);

			// 4. Verifica si la firma coincide con los valores de g,p y g2x
            String signature = dc.readLine();
			String mensaje = str_g + "," + str_p +"," + str_g2x;
			byte[] firma = str2byte(signature);
			
			boolean verificacion = f.checkSignature(publicaServidor, firma, mensaje);

			// 5. Envia "OK" o "ERROR" dependiendo de la verificacion
			if(verificacion == true){
				ac.println("OK");
			}
			else{
				ac.println("ERROR");
				return;
			}

			// 6a. Generar G^y
			SecureRandom r = new SecureRandom();
			int y = Math.abs(r.nextInt());
			
    		Long longy = Long.valueOf(y);
    		BigInteger biy = BigInteger.valueOf(longy);
    		BigInteger valor_comun = G2Y(g,biy,p);
    		String str_valor_comun = valor_comun.toString();
    		System.out.println(dlg + "G2Y: "+str_valor_comun);

			// 6b. manda G2Y
			ac.println(str_valor_comun);
			
			// 7a. 
			// computing (G^x)^y mod N
    		BigInteger llave_maestra = calcular_llave_maestra(g2x,biy,p);
    		String str_llave = llave_maestra.toString();
    		System.out.println(dlg + " llave maestra: " + str_llave);
    		
    		// generating symmetric key
			SecretKey sk_clnt = f.csk1(str_llave);
			SecretKey sk_mac = f.csk2(str_llave);
			
			// generate iv1
			byte[] iv1 = generateIvBytes();
			String str_iv1 = byte2str(iv1);
			IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
			
			// Cifrar mensaje
			Random random = new Random();
			int valorParaConsultar = random.nextInt(100)+1;
			
			/*
			BigInteger bi_valor = BigInteger.valueOf(valorParaConsultar);
			byte[] byte_valor = bi_valor.toByteArray();
			*/
			String str_valor = String.valueOf(valorParaConsultar);
			byte[] byte_valor = str_valor.getBytes();
			byte[] consulta_cifrada = f.senc(byte_valor, sk_clnt, ivSpec1, "Cliente");
			byte [] consulta_mac = f.hmac(byte_valor, sk_mac);
			
			// 7b. Servidor calcula la llave maestra, la llave simetrica para cifrar y la llave simetrica para HMAC y genera iv2
			
			// 8. Enviar consulta cifrada, hmac, iv1
			String m1 = byte2str(consulta_cifrada);
        	String m2 = byte2str(consulta_mac);
        	ac.println(m1);
        	ac.println(m2);
			ac.println(str_iv1);
			
			// 9. El servidor verifica
			// 10. El servidor responde con "OK" o "ERROR"
			linea = dc.readLine();
			if (linea.compareTo("ERROR")==0) {
				System.out.println("El servidor respondió 'ERROR'");
				return;
				
			} else if (linea.compareTo("OK")==0) {
				
				//11. Listen Cifrado_rta, hmac_respuesta, iv2
				String str_rta = dc.readLine();
				String str_mac = dc.readLine();
				String str_iv2 = dc.readLine();
				
				byte[] byte_rta = str2byte(str_rta);
				byte[] byte_mac = str2byte(str_mac);
				byte[] iv2 = str2byte(str_iv2);
				IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
				
				// 12. Descifrar y verificar
				byte[] descifrado = f.sdec(byte_rta, sk_clnt,ivSpec2);
		    	boolean verificar = f.checkInt(descifrado, sk_mac, byte_mac);
		    	System.out.println(dlg + "Integrity check:" + verificar);
		    	
		    	if (verificar) {
		    		System.out.println("VERIFICACIÓN EXITOSA");
		    		String str_original = new String(descifrado, StandardCharsets.UTF_8);
		    		int valor = Integer.parseInt(str_original);
		    		System.out.println(dlg + "Query answer:" + valor);
		    		if (valorParaConsultar+1 == valor) { //verifica que el valor recibido sea el valor enviado +1
		    			String mensajeExito = "OK";
		    			// 13. "OK"
		    			ac.println(mensajeExito);
		    			exito = true;
		    		} else {
		    			// 13. "ERROR"
		    			String mensajeError = "ERROR";
			    		ac.println(mensajeError);
			    		System.out.println("ERROR: el numero recibido no es el numero enviado +1");
			    		return;
		    		}
		    		
		    		
		    	} else {
		    		// 13. "ERROR"
		    		String mensajeError = "ERROR";
		    		ac.println(mensajeError);
		    		System.out.println("ERROR en la verificación");
		    		return;
		    	}
				
				
			}
			
			
			
			
	        sc.close();
	    } catch (Exception e) {
			 e.printStackTrace(); }

	
        
    }  
    
	private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
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
	
	private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}
}

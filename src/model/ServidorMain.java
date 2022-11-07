package model;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class ServidorMain {
	
	private static ServerSocket ss;	
	private static final String ID = "Main Server: ";
	private static int puerto = 4030;

	public static void main(String[] args) throws IOException {
		
		System.out.println(ID + "Starting main server. Port: " + puerto);
		//Inicializa el primer thread
		int idThread = 0;
		//Crea el socket con el que se conecta con el cliente
		ss = new ServerSocket(puerto);
		System.out.println(ID + "Creating socket: done");
		String options = "210";
		
		while (true) {
		    Random optRandom = new Random();
			int opt = optRandom.nextInt()%6;
			if (idThread%3==0) {
				switch (opt) {
				case 0:
					options = "012";
					break;
				case 1:
					options = "021";
					break;
				case 2: 
					options = "102";
					break;
				case 3:
					options = "120";
					break;
				case 4:
					options = "201";
					break;
				default:
					options = "210";
					break;
				}
			}

			try { 
				// Crea un delegado por cliente. Atiende por conexion. 
				//semaforo.acquire();
				//Recibe lo que envío el cliente
				Socket sc = ss.accept();
				System.out.println(ID + " delegate " + idThread + ": accepting client - done");
				// Genera al azar la opción del servidor que se va a ejecutar 
				int pos = idThread % 3;
				int mod = options.charAt(pos) - '0';
				//Arranca el thread que va a atender al cliente que aceptó
				SrvThread d = new SrvThread(sc,idThread,mod);
				idThread++;
				d.start();
			} catch (IOException e) {
				System.out.println(ID + " delegate " + idThread + ": accepting client - ERROR");
				e.printStackTrace();
			}
		}

	}

}

package ar.edu.tadp.firewall.implementations;

import ar.edu.tadp.firewall.AcceptListener;
import ar.edu.tadp.firewall.Address;
import ar.edu.tadp.firewall.BloqueoListener;
import ar.edu.tadp.firewall.Forwarder;
import ar.edu.tadp.firewall.Request;

public class BasicHandler implements Forwarder, AcceptListener, BloqueoListener {

	@Override
	public void forward(Request r, Address address) {
		System.out.println("Redirigiendo " + r + " a " + address);
	}

	@Override
	public void requestBloqueado(Request request) {
		System.out.println("bloqueando " + request);		
	}

	@Override
	public void requestAceptado(Request r) {
		System.out.println("aceptando " + r);				
	}

}

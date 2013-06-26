package ar.edu.tadp.firewall;

import java.util.HashSet;
import java.util.Set;

import junit.framework.Assert;

import ar.edu.tadp.firewall.implementations.BasicHandler;

public class MockHandler implements Forwarder, AcceptListener, BloqueoListener {

	private Set<Request> bloqueados = new HashSet<Request>();
	private Set<Request> redirigidos = new HashSet<Request>();
	private Set<Request> aceptados = new HashSet<Request>();

	
	@Override
	public void requestAceptado(Request r) {
		this.aceptados.add(r);
	}
	
	@Override
	public void requestBloqueado(Request request) {
		this.bloqueados.add(request);
	}

	@Override
	public void forward(Request r, Address address) {
		this.redirigidos.add(r);
	}

	
	public void assertBloqueado(Request r) {
		Assert.assertTrue(bloqueados.contains(r));
	}

	public void assertRedirigido(Request r) {
		Assert.assertTrue(redirigidos.contains(r));
	}
	
	public void assertAceptado(Request r) {
		Assert.assertTrue(aceptados.contains(r));
	}

}
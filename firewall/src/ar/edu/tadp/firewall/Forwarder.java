package ar.edu.tadp.firewall;

public interface Forwarder {

	void forward(Request r, Address address);
}

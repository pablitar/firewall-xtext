package ar.edu.tadp.firewall.rules;

import ar.edu.tadp.firewall.Address;
import ar.edu.tadp.firewall.Forwarder;
import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.rules.Action;

public class ForwardAction implements Action<Request> {

	private Forwarder forwarder;
	private Address address;

	public Address getAddress() {
		return address;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

	public ForwardAction() {
	}

	public ForwardAction(Forwarder forwarder, Address address) {
		this.forwarder = forwarder;
		this.address = address;
	}

	public Forwarder getForwarder() {
		return forwarder;
	}

	public void setForwarder(Forwarder forwarder) {
		this.forwarder = forwarder;
	}

	@Override
	public void perform(Request t) {
		this.forwarder.forward(t, address);
	}

}

package ar.edu.tadp.firewall.conditions;

import ar.edu.tadp.firewall.Request;

public class PortCondition extends AddressCondition {

	private int port;
	
	public PortCondition(int port, AddressType addressType) {
		super(addressType);
		this.port = port;
	}
	
	public PortCondition() {
	}
	
	@Override
	public boolean match(Request param) {
		return this.getAddressType().getPort(param) == port;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}


}

package ar.edu.tadp.firewall.conditions;

import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.rules.Condition;

public class PortRangeCondition extends AddressCondition {

	private int from;
	private int to;

	public PortRangeCondition(int from, int to, AddressType addressType) {
		super(addressType);
		this.setTo(to);
		this.setFrom(from);
	}

	public PortRangeCondition() {
	}

	@Override
	public boolean match(Request param) {
		int port = this.getAddressType().getPort(param);
		return this.getFrom() <= port && port <= this.getTo();
	}

	public int getFrom() {
		return from;
	}

	public void setFrom(int from) {
		this.from = from;
	}

	public int getTo() {
		return to;
	}

	public void setTo(int to) {
		this.to = to;
	}


}

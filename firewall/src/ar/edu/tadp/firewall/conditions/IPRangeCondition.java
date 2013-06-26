package ar.edu.tadp.firewall.conditions;

import ar.edu.tadp.firewall.IP;
import ar.edu.tadp.firewall.Request;

public class IPRangeCondition extends AddressCondition {

	private IP from;
	private IP to;
	
	
	public IPRangeCondition() {
		super();
	}

	public IPRangeCondition(AddressType addressType, IP from, IP to) {
		super(addressType);
		this.from = from;
		this.to = to;
	}

	public IPRangeCondition(AddressType addressType, String from, String to) {
		this(addressType, new IP(from), new IP(to));
	}
	
	@Override
	public boolean match(Request param) {
		IP ip = this.getAddressType().getIP(param);
		return this.from.compareTo(ip) <= 0 && ip.compareTo(this.to) <=0;
	}

	public IP getFrom() {
		return from;
	}

	public void setFrom(IP from) {
		this.from = from;
	}

	public IP getTo() {
		return to;
	}

	public void setTo(IP to) {
		this.to = to;
	}


}

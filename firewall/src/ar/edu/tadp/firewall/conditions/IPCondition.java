package ar.edu.tadp.firewall.conditions;

import ar.edu.tadp.firewall.IP;
import ar.edu.tadp.firewall.Request;

public class IPCondition extends AddressCondition{

	private IP ip;
	
	public IPCondition() {
		super();
	}

	public IPCondition(IP ip, AddressType addressType) {
		super(addressType);
		this.setIp(ip);
	}

	public IPCondition(String ip, AddressType addressType) {
		this(new IP(ip), addressType);
	}
	
	@Override
	public boolean match(Request param) {
		return this.getAddressType().getIP(param).equals(this.getIp());
	}

	private Object getIp() {
		return this.ip;
	}

	public void setIp(IP ip) {
		this.ip = ip;
	}

}

package ar.edu.tadp.firewall.conditions;

import ar.edu.tadp.firewall.Address;
import ar.edu.tadp.firewall.IP;
import ar.edu.tadp.firewall.Request;

public enum AddressType {
	SOURCE {
		@Override
		public Address getAddress(Request request) {
			return request.getSource();
		}
	},
	DESTINATION {

		@Override
		public Address getAddress(Request request) {
			return request.getDestination();
		}

	};

	public abstract Address getAddress(Request request);

	public int getPort(Request request) {
		return this.getAddress(request).getPort();
	};

	public IP getIP(Request request) {
		return this.getAddress(request).getIp();
	};

}

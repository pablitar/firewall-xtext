package ar.edu.tadp.firewall.conditions;

import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.rules.Condition;

public abstract class AddressCondition implements Condition<Request> {

	private AddressType addressType;

	public AddressCondition() {

	}

	public AddressCondition(AddressType addressType) {
		this.addressType = addressType;
	}

	public AddressType getAddressType() {
		return addressType;
	}

	public void setAddressType(AddressType addressType) {
		this.addressType = addressType;
	}

}

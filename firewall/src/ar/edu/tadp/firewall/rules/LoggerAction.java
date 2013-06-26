package ar.edu.tadp.firewall.rules;

import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.rules.Action;

public class LoggerAction implements Action<Request> {

	private String prefix = "";
	
	public LoggerAction(String prefix) {
		this.setPrefix(prefix);
	}

	public LoggerAction() {
	}
	
	@Override
	public void perform(Request t) {
		System.out.println(getPrefix() + t);
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

}

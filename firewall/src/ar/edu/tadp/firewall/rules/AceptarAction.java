package ar.edu.tadp.firewall.rules;

import ar.edu.tadp.firewall.AcceptListener;
import ar.edu.tadp.firewall.MockHandler;
import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.rules.Action;

public class AceptarAction implements Action<Request> {

	private AcceptListener listener;
	
	public AceptarAction(AcceptListener listener) {
		this.setListener(listener);
	}

	@Override
	public void perform(Request t) {
		getListener().requestAceptado(t);
	}

	public AcceptListener getListener() {
		return listener;
	}

	public void setListener(AcceptListener listener) {
		this.listener = listener;
	}

}

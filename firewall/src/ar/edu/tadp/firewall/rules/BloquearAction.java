package ar.edu.tadp.firewall.rules;

import ar.edu.tadp.firewall.BloqueoListener;
import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.rules.Action;

public class BloquearAction implements Action<Request> {

	private BloqueoListener listener;

	public BloquearAction(BloqueoListener listener) {
		super();
		this.listener = listener;
	}

	@Override
	public void perform(Request t) {
		this.getListener().requestBloqueado(t);
	}

	public BloqueoListener getListener() {
		return listener;
	}

	public void setListener(BloqueoListener listener) {
		this.listener = listener;
	}

}

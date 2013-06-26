package edu.tadp.firewall;

import org.eclipse.emf.common.util.URI;
import org.eclipse.emf.ecore.resource.Resource;
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl;

import ar.edu.tadp.firewall.Firewall;
import ar.edu.tadp.firewall.Request;
import ar.edu.tadp.firewall.conditions.AddressType;
import ar.edu.tadp.firewall.conditions.IPCondition;
import ar.edu.tadp.firewall.conditions.PortCondition;
import ar.edu.tadp.firewall.implementations.BasicHandler;
import ar.edu.tadp.firewall.rules.AceptarAction;
import ar.edu.tadp.firewall.rules.BloquearAction;
import ar.edu.tadp.firewall.rules.LoggerAction;
import ar.edu.tadp.rules.Action;
import ar.edu.tadp.rules.BasicRule;
import ar.edu.tadp.rules.Condition;
import ar.edu.tadp.rules.ExclusiveRuleChain;
import edu.tadp.firewall.firewalll.Accion;
import edu.tadp.firewall.firewalll.AceptarAccion;
import edu.tadp.firewall.firewalll.BloquearAccion;
import edu.tadp.firewall.firewalll.Condicion;
import edu.tadp.firewall.firewalll.CondicionIP;
import edu.tadp.firewall.firewalll.CondicionPuerto;
import edu.tadp.firewall.firewalll.IP;
import edu.tadp.firewall.firewalll.LoggearAccion;
import edu.tadp.firewall.firewalll.Regla;

public class FirewallCreatorOld {
	private static boolean inited;

	public static Firewall createFirewall(String modelFile) {
		if(!inited){
			init();
		}
		
		Resource r = new ResourceSetImpl().getResource(
				URI.createFileURI(modelFile), true);

		edu.tadp.firewall.firewalll.Firewall e = (edu.tadp.firewall.firewalll.Firewall) r
				.getContents().get(0);

		Firewall firewall = new Firewall();
		ExclusiveRuleChain<Request> chain = new ExclusiveRuleChain<Request>();
		firewall.addRule(chain);

		for (Regla reglaNode : e.getReglas()) {
			chain.add(createRule(reglaNode));
		}

		return firewall;
	}

	private static void init() {
		new FirewalllStandaloneSetupGenerated().createInjectorAndDoEMFRegistration();
		inited = true;
	}

	private static ar.edu.tadp.rules.Rule<Request> createRule(Regla rule) {
		Condition<Request> c = createCondition(rule.getCondicion());
		Action<Request> a = createAction(rule.getAccion());
		return new BasicRule<Request>(c, a);
	}

	private static Action<Request> createAction(Accion accion) {
		if (accion instanceof AceptarAccion) {
			return new AceptarAction(new BasicHandler());
		} else if (accion instanceof BloquearAccion){
			return new BloquearAction(new BasicHandler());
		} else {
			return new LoggerAction(((LoggearAccion)accion).getPrefijo());
		}
	}

	private static Condition<Request> createCondition(Condicion condicion) {
		if (condicion instanceof CondicionPuerto) {
			CondicionPuerto c = (CondicionPuerto) condicion;
			return new PortCondition(c.getName(), AddressType.SOURCE);
		} else {
			CondicionIP c = (CondicionIP) condicion;
			IP ip = c.getIp();

			return new IPCondition(String.format("%d.%d.%d.%d",
					ip.getPrimero(), ip.getSegundo(), ip.getTercero(),
					ip.getCuarto()), AddressType.SOURCE);
		}
	}
}

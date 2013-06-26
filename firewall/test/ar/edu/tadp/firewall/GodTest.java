package ar.edu.tadp.firewall;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import ar.edu.tadp.firewall.conditions.AddressType;
import ar.edu.tadp.firewall.conditions.IPCondition;
import ar.edu.tadp.firewall.conditions.PortCondition;
import ar.edu.tadp.firewall.conditions.PortRangeCondition;
import ar.edu.tadp.firewall.implementations.BasicHandler;
import ar.edu.tadp.firewall.rules.AceptarAction;
import ar.edu.tadp.firewall.rules.BloquearAction;
import ar.edu.tadp.firewall.rules.LoggerAction;
import ar.edu.tadp.rules.BasicRule;
import ar.edu.tadp.rules.CompositeAction;
import ar.edu.tadp.rules.Condition;
import ar.edu.tadp.rules.ExclusiveRuleChain;
import ar.edu.tadp.rules.Rule;
import ar.edu.tadp.rules.conditions.And;
import ar.edu.tadp.rules.conditions.CompositeCondition;

/**
 * REFACTORME!!! hacer muchos test en lugar de uno grande Perdón, ando sin
 * tiempo de hacer muchos test unitarios
 */
public class GodTest {

	private Firewall firewall;
	private MockHandler basicHandler;
	private boolean always = false;
	@Test
	public void testBloquear() {
		Request r = new Request("192.168.1.1", 3456, "192.168.1.2", 80);
		firewall.receive(r);
		basicHandler.assertBloqueado(r);
		Assert.assertTrue(always);
	}

	@Test
	public void testAceptar() {
		Request r = new Request("127.0.0.1", 3456, "192.168.1.2", 80);
		firewall.receive(r);
		basicHandler.assertAceptado(r);
		Assert.assertTrue(always);
	}

	@Before
	public void createFirewall() {
		basicHandler = new MockHandler();
		firewall = new Firewall();
		ExclusiveRuleChain<Request> chain = new ExclusiveRuleChain<Request>();
		chain.add(createAceptar80DesdeLocalhost());
		chain.add(createBloquearMenorA1024());
		firewall.addRule(chain);
		firewall.addRule(new Rule<Request>() {

			@Override
			public boolean apply(Request param) {
				always = true;
				return true;
			}
		});
	}

	private BasicRule<Request> createBloquearMenorA1024() {
		PortRangeCondition menorA1024Condition = new PortRangeCondition(0,
				1024, AddressType.DESTINATION);
		CompositeAction<Request> bloquearAction = new CompositeAction<Request>();
		bloquearAction.add(new BloquearAction(basicHandler));
		bloquearAction.add(new LoggerAction("Se bloqueo el pedido: "));

		BasicRule<Request> bloquearMenorA1024 = new BasicRule<Request>();
		bloquearMenorA1024.setAction(bloquearAction);
		bloquearMenorA1024.setCondition(menorA1024Condition);
		return bloquearMenorA1024;
	}

	private Rule<Request> createAceptar80DesdeLocalhost() {
		CompositeCondition<Request> aceptar80ConditionDesdeLocalhost = new And<Request>();
		aceptar80ConditionDesdeLocalhost.add(new PortCondition(80,
				AddressType.DESTINATION));
		aceptar80ConditionDesdeLocalhost.add(new IPCondition("127.0.0.1",
				AddressType.SOURCE));
		
		
		CompositeAction<Request> aceptarAction = new CompositeAction<Request>();
		aceptarAction.add(new AceptarAction(this.basicHandler));
		aceptarAction.add(new LoggerAction("Pedido aceptado:"));

		BasicRule<Request> bloquearMenorA1024 = new BasicRule<Request>();
		bloquearMenorA1024.setAction(aceptarAction);
		bloquearMenorA1024.setCondition(aceptar80ConditionDesdeLocalhost);
		return bloquearMenorA1024;
	}


}

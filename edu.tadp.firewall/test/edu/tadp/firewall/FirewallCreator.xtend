package edu.tadp.firewall

import ar.edu.tadp.firewall.conditions.AddressType
import ar.edu.tadp.firewall.conditions.IPCondition
import ar.edu.tadp.firewall.conditions.PortCondition
import ar.edu.tadp.rules.BasicRule
import ar.edu.tadp.rules.Condition
import ar.edu.tadp.rules.ExclusiveRuleChain
import ar.edu.tadp.rules.Rule
import edu.tadp.firewall.firewalll.Condicion
import edu.tadp.firewall.firewalll.CondicionIP
import edu.tadp.firewall.firewalll.CondicionPuerto
import edu.tadp.firewall.firewalll.Firewall
import edu.tadp.firewall.firewalll.Regla
import org.eclipse.emf.common.util.URI
import org.eclipse.emf.ecore.resource.impl.ResourceSetImpl

import static extension edu.tadp.firewall.FirewallCreatorV2.*
import edu.tadp.firewall.firewalll.Accion
import ar.edu.tadp.firewall.rules.AceptarAction
import edu.tadp.firewall.firewalll.BloquearAccion
import edu.tadp.firewall.firewalll.LoggearAccion
import ar.edu.tadp.firewall.implementations.BasicHandler
import ar.edu.tadp.firewall.rules.BloquearAction
import ar.edu.tadp.firewall.rules.LoggerAction
import ar.edu.tadp.rules.Action
import ar.edu.tadp.firewall.Request

class FirewallCreatorV2 {
	static boolean inited
	def static createFirewall(String modelFile) {
		init()
		
		var r = new ResourceSetImpl().getResource(URI::createFileURI(modelFile), true)
		
		var root = r.getContents().get(0) as Firewall;
		
		var builtFirewall = new ar.edu.tadp.firewall.Firewall()
		var rootChain = new ExclusiveRuleChain<Request>()
		
		builtFirewall.addRule(rootChain);
		
		for (Regla reglaNode: root.reglas) {
			rootChain.add(createRule(reglaNode));
		}
		
		return builtFirewall
	}
	
	def static Rule<Request> createRule(Regla regla) { 
		var condicion = createCondition(regla.getCondicion())
		var accion = createAction(regla.getAccion())
		return new BasicRule(condicion, accion)
	}
	
	def static Action createAction(Accion accion) { }

	def static Action createAction(AceptarAction accion) { new AceptarAction(new BasicHandler) }
	def static Action createAction(BloquearAccion accion) { new BloquearAction(new BasicHandler) }
	def static Action createAction(LoggearAccion accion) { new LoggerAction(accion.prefijo) }
	
	def static Condition createCondition(CondicionPuerto condicionPuerto) {
		new PortCondition(condicionPuerto.name, AddressType::SOURCE)		
	}
	
	def static Condition createCondition(CondicionIP condicionIP) {
		var ip = condicionIP.ip
		new IPCondition('''«ip.primero».«ip.segundo».«ip.tercero».«ip.cuarto»''', AddressType::SOURCE)	
	}

	def static Condition createCondition(Condicion c){ }
	
	def static init() {
		if(!inited) {
			new FirewalllStandaloneSetupGenerated().createInjectorAndDoEMFRegistration()
			inited = true
		}
	}
}
package edu.tadp.firewall.validation;

import org.eclipse.emf.ecore.EStructuralFeature;
import org.eclipse.xtext.validation.Check;

import edu.tadp.firewall.firewalll.FirewalllPackage;
import edu.tadp.firewall.firewalll.IP;

public class FirewalllJavaValidator extends AbstractFirewalllJavaValidator {

	@Check
	public void checkIP(IP ip) {

		check(ip, ip.getPrimero(), FirewalllPackage.Literals.IP__PRIMERO);
		check(ip, ip.getSegundo(), FirewalllPackage.Literals.IP__SEGUNDO);
		check(ip, ip.getTercero(), FirewalllPackage.Literals.IP__TERCERO);
		check(ip, ip.getCuarto(), FirewalllPackage.Literals.IP__CUARTO);

	}

	private void check(IP ip, int ipElement, EStructuralFeature feature) {
		if(ipElement< 0 || ipElement > 255) {
			error("Los números de las ips deben estar entre 0 y 255", feature);
		}
	}

}

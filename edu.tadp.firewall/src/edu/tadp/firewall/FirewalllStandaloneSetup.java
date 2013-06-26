
package edu.tadp.firewall;

/**
 * Initialization support for running Xtext languages 
 * without equinox extension registry
 */
public class FirewalllStandaloneSetup extends FirewalllStandaloneSetupGenerated{

	public static void doSetup() {
		new FirewalllStandaloneSetup().createInjectorAndDoEMFRegistration();
	}
}


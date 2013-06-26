package edu.tadp.firewall;

import org.junit.Test;

import ar.edu.tadp.firewall.Firewall;

public class FirewallCreatorTest {
	
	@Test
	public void testCreateFirewall() {
		Firewall aFirewall = FirewallCreatorV2.createFirewall("aFirewall.firewall");
		
		aFirewall.toString();
	}

}

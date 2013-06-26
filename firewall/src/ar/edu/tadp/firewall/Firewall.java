package ar.edu.tadp.firewall;

import java.util.ArrayList;
import java.util.List;

import ar.edu.tadp.rules.Rule;

public class Firewall {
	
	private List<Rule<Request>> rules = new ArrayList<Rule<Request>>();
	
	public Firewall() {
		// TODO Auto-generated constructor stub
	}
	
	public Firewall(List<Rule<Request>> rules) {
		this.rules = rules;}
	
	public void receive(Request param) {
		for(Rule<Request> rule: rules) {
			rule.apply(param);
		}		
	}
	
	public void addRule(Rule<Request> rule) {
		this.rules.add(rule);
	}
}

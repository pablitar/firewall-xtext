package ar.edu.tadp.rules;

import java.util.ArrayList;
import java.util.List;

//TODO Es muy parecido a un andCondition, se podria extraer algo en comun?
public class ExclusiveRuleChain<T> implements Rule<T>{

	private List<Rule<T>> rules = new ArrayList<Rule<T>>();
	
	@Override
	public boolean apply(T param) {
		
		for(Rule<T> rule : rules) {
			if(rule.apply(param)) {
				return true;
			}
		}
		return false;
	}
	
	public void add(Rule<T> rule) {
		this.rules.add(rule);
	}

}

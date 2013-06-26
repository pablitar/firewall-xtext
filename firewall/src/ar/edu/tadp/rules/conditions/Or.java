package ar.edu.tadp.rules.conditions;

import ar.edu.tadp.rules.Condition;

public class Or<T> extends CompositeCondition<T> {

	@Override
	public boolean match(T param) {
		for(Condition<T> condition : this.getConditions()) {
			if(condition.match(param)) {
				return true;
			}
		}
		return false;
	}

}

package ar.edu.tadp.rules.conditions;

import ar.edu.tadp.rules.Condition;

public class Not<T> implements Condition<T>{

	private Condition<T> condition;

	public Not(Condition<T> condition) {
		this.condition = condition;
	}

	public Not() {
	}

	
	@Override
	public boolean match(T param) {
		return !this.condition.match(param);
	}

	public Condition<T> getCondition() {
		return condition;
	}

	public void setCondition(Condition<T> condition) {
		this.condition = condition;
	}

	
}

package ar.edu.tadp.rules.conditions;

import java.util.ArrayList;
import java.util.List;

import ar.edu.tadp.rules.Condition;

public abstract class CompositeCondition<T> implements Condition<T> {
	
	private List<Condition<T>> conditions = new ArrayList<Condition<T>>();
	
	public CompositeCondition() {
	}
	
	public CompositeCondition(List<Condition<T>> condition) {
		this.conditions = condition;
	}
	
	@Override
	public abstract boolean match(T param);

	public void add(Condition<T> condition) {
		this.conditions.add(condition);
	}
	public List<Condition<T>> getConditions() {
		return conditions;
	}
	public void setConditions(List<Condition<T>> conditions) {
		this.conditions = conditions;
	}
}

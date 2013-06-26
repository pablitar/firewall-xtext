package ar.edu.tadp.rules;

public class BasicRule<T> implements Rule<T> {

	private Action<T> action;
	private Condition<T> condition;

	public BasicRule() {
	}

	public BasicRule(Condition<T> condition, Action<T> action) {
		super();
		this.action = action;
		this.condition = condition;
	}
	
	public boolean apply(T param) {
		boolean apply = this.getCondition().match(param);
		if(apply) {
			this.action.perform(param);
		}
		return apply;
	}

	public Action<T> getAction() {
		return action;
	}

	public void setAction(Action<T> action) {
		this.action = action;
	}

	public Condition<T> getCondition() {
		return condition;
	}

	public void setCondition(Condition<T> condition) {
		this.condition = condition;
	}
}

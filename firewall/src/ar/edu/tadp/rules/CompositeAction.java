package ar.edu.tadp.rules;

import java.util.ArrayList;
import java.util.List;

public class CompositeAction<T> implements Action<T> {

	private List<Action<T>> actions = new ArrayList<Action<T>>();

	public CompositeAction() {
	}

	public CompositeAction(List<Action<T>> actions) {
		this.actions = actions;
	}

	public List<Action<T>> getActions() {
		return actions;
	}

	public void setActions(List<Action<T>> actions) {
		this.actions = actions;
	}

	@Override
	public void perform(T t) {
		for(Action<T> action : this.actions) {
			action.perform(t);
		}
	}
	
	public void add(Action<T> action) {
		this.actions.add(action);
	}
}

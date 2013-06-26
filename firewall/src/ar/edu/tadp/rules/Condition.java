package ar.edu.tadp.rules;

public interface Condition<T> {

	public boolean match(T param);
}

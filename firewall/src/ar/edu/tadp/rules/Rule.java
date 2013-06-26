package ar.edu.tadp.rules;

public interface Rule<T> {

	/**
	 * La regla puede aplicarse o no segun decision interna
	 * @param param
	 * @return
	 */
	public boolean apply(T param);
	
}

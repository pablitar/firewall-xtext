package ar.edu.tadp.firewall;

public class Request {


	private Address source;
	private Address destination;

	public Request() {
		// TODO Auto-generated constructor stub
	}

	public Request(Address source, Address destination) {
		this.source = source;
		this.destination = destination;
	}

	public Request(String sourceHost, int sourcePort, String destinationHost,
			int destinationPort) {
		this(new Address(sourceHost, sourcePort), new Address(destinationHost,
				destinationPort));
	}

	public Address getSource() {
		return source;
	}

	public void setSource(Address source) {
		this.source = source;
	}

	public Address getDestination() {
		return destination;
	}

	public void setDestination(Address destination) {
		this.destination = destination;
	}

	@Override
	public String toString() {
		return "Request [source=" + source + ", destination=" + destination
				+ "]";
	}
}

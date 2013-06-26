package ar.edu.tadp.firewall;


public class IP implements Comparable<IP>{

	private String value;
	private long longValue;

	public IP(Long longValue) {
		this.longValue = longValue;
		value = ((longValue >> 24) & 0xFF) + "." + ((longValue >> 16) & 0xFF)
				+ "." + ((longValue >> 8) & 0xFF) + "." + (longValue & 0xFF);
	}

	public IP(String value) {
			this.value = value;
			String[] addrArray = value.split("\\.");
	        long num = 0; 
	        for (int i = 0; i < addrArray.length; i++) { 
	            int power = 3 - i;
	            num += ((Integer.parseInt(addrArray[i]) % 256 * Math.pow(256, power))); 
	        } 
			longValue = num;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (longValue ^ (longValue >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		IP other = (IP) obj;
		if (longValue != other.longValue)
			return false;
		return true;
	}

	@Override
	public int compareTo(IP arg0) {
		return ((Long)this.longValue).compareTo(arg0.longValue);
	}
	
	public long getLongValue() {
		return longValue;
	}
	public String getValue() {
		return value;
	}
	@Override
	public String toString() {
		return value;
	}

}

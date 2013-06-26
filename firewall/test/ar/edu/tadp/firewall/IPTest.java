package ar.edu.tadp.firewall;

import org.junit.Assert;
import org.junit.Test;

public class IPTest {

	@Test
	public void testIPString() {
		String value = "123.154.34.2";
		Assert.assertEquals(value, new IP(new IP(value).getLongValue()).getValue());
	}

	@Test
	public void testIPLong() {
		long value = 7632412;
		Assert.assertEquals(value, new IP(new IP(value).getValue()).getLongValue());
	}

}

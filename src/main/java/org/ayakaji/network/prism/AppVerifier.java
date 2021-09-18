package org.ayakaji.network.prism;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;

public class AppVerifier {

	private static String getV4InetAddrs() throws SocketException {
		Map<String, String> mapAddrs = new LinkedHashMap<String, String>();
		for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
			if ((!nic.isLoopback()) && nic.isUp()) {
				for (InterfaceAddress infAddr : nic.getInterfaceAddresses()) {
					if (infAddr.getAddress() instanceof Inet4Address) {
						mapAddrs.put(infAddr.getAddress().getHostAddress(),
								Short.toString(infAddr.getNetworkPrefixLength()));
					}
				}
			}
		}
		return JSON.toJSONString(mapAddrs, true);
	}

	private static String getMask(int prefix) {
		if (prefix > 32)
			prefix = 32;
		else if (prefix < 0)
			prefix = 0;
		String binary = String.format("%0" + prefix + "d", 0).replace("0", "1")
				+ String.format("%0" + (32 - prefix) + "d", 0);
		return Integer.valueOf(binary.substring(0, 8), 2) + "." + Integer.valueOf(binary.substring(8, 16), 2) + "."
				+ Integer.valueOf(binary.substring(16, 24), 2) + "." + Integer.valueOf(binary.substring(24, 32), 2);
	}

	public static void main(String[] args) throws InterruptedException, IOException {
//		System.out.println(getV4InetAddrs());
//		System.out.println(getMask(28));
		String appPath = System.getProperty("user.dir");
		Path dmpPath = Paths.get(appPath, "policy.json");
	}
}
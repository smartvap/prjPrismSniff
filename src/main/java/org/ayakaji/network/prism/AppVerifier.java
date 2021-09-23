package org.ayakaji.network.prism;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;

@SuppressWarnings("unused")
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

	public static String GetSerNum() {
		String[] command = null;
		String osName = System.getProperty("os.name").toLowerCase();
		if (osName.contains("windows"))
			command = new String[] { "cmd", "/c", "src\\main\\native\\dmidecode.exe -s system-serial-number" };
		else if (osName.contains("linux"))
			command = new String[] { "/bin/sh", "-c", "dmidecode -s system-serial-number" };
		String sNum = null;
		try {
			Process SerNumProcess = Runtime.getRuntime().exec(command);
			BufferedReader sNumReader = new BufferedReader(new InputStreamReader(SerNumProcess.getInputStream()));
			sNum = sNumReader.readLine().trim();
			SerNumProcess.waitFor();
			sNumReader.close();
		} catch (Exception ex) {
			ex.printStackTrace();
			sNum = "Did not work!";
		}
		return sNum;
	}

	public static void main(String[] args) throws InterruptedException, IOException {
//		System.out.println(getV4InetAddrs());
//		System.out.println(getMask(28));
//		String appPath = System.getProperty("user.dir");
//		Path dmpPath = Paths.get(appPath, "policy.json");
//		System.out.println(GetSerNum());
//		File folder = new File("");
//		System.out.println(folder.getAbsolutePath());
//		File folder = new File(".");
//		FileFilter ff = new FileFilter() {
//			@Override
//			public boolean accept(File file) {
//				String s = file.getName().toLowerCase();
//				if (s.startsWith("plc-") && s.endsWith(".json")) {
//					return true;
//				}
//				return false;
//			}
//		};
//		for (File f : folder.listFiles(ff)) {
//			System.out.println(f.getName().split("\\.")[0]);
//		}
//		File[] files = folder.listFiles();
//		for (File f : files) {
//			System.out.println(f.getName());
//		}
		System.out.println("plc_c774b658713942dbb1eadaea422d3737".substring(0,30));
	}
}

package org.ayakaji;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import com.alibaba.fastjson.JSONObject;

public class PortSniffer {

	private final static Logger logger = Logger.getLogger(PortSniffer.class.getName());
	private final static String IPV4 = "^((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}$";
	private final static String IP_MASK = "^((128|192)|2(24|4[08]|5[245]))(\\.(0|(128|192)|2((24)|(4[08])|(5[245])))){3}$";

	public static boolean isIp(String ip) {
		if (ip == null)
			return false;
		Pattern patt = Pattern.compile(IPV4);
		return patt.matcher(ip).matches();
	}

	public static boolean isIpMask(String mask) {
		if (mask == null)
			return false;
		Pattern patt = Pattern.compile(IP_MASK);
		return patt.matcher(mask).matches();
	}

	public static boolean isOpen(String host, int port) {
		Socket sock = new Socket();
		try {
			sock.connect(new InetSocketAddress(host, port), 1000);
			sock.setSoTimeout(1000);
			sock.close();
			sock = null;
			return true;
		} catch (IOException e) {
			sock = null;
			return false;
		}
	}

	public static void binaryArrayPlus(byte[] binaryArray, int plus) {
		binaryArrayPlus(binaryArray, binaryArray.length - 1, plus);
	}

	private static void binaryArrayPlus(byte[] binaryArray, int index, int plus) {
		if (index < 0) {
			binaryArray[0] = 0;
			return;
		}
		binaryArray[index] = (byte) (binaryArray[index] + 1);
		plus--;
		if (binaryArray[index] > 1) {
			binaryArrayPlus(binaryArray, index - 1, 1);
			binaryArray[index] = 0;
		}
		if (plus > 0)
			binaryArrayPlus(binaryArray, index, plus);
	}

	public static String[] getIpBinary(String ip) {
		String[] strs = ip.split("\\.");
		for (int i = 0; i < 4; i++) {
			strs[i] = Integer.toBinaryString(Integer.parseInt(strs[i]));
			if (strs[i].length() < 8) {
				StringBuilder zero = new StringBuilder();
				for (int j = 0; j < 8 - strs[i].length(); j++)
					zero.append("0");
				strs[i] = zero.toString() + strs[i];
			}
		}
		return strs;
	}

	public static byte[] toBinary(String[] binaryStrArr) {
		int bl = binaryStrArr[0].length();
		byte[] bytes = new byte[bl * binaryStrArr.length];
		for (int i = 0; i < binaryStrArr.length; i++) {
			for (int j = 0; j < bl; j++)
				bytes[i * bl + j] = (byte) (binaryStrArr[i].charAt(j) == '1' ? 1 : 0);
		}
		return bytes;
	}

	public static List<String> getLocalAreaIpList(String ip, String mask) {
		return getLocalAreaIpList(ip, mask, false);
	}

	public static List<String> getLocalAreaIpList(String ip, String mask, boolean containParamIp) {
		return getLocalAreaIpList(ip, mask, containParamIp, false);
	}

	public static List<String> getLocalAreaIpList(String ip, String mask, boolean containParamIp,
			boolean ignoreFirstAndLastIp) {
		if (!isIp(ip) || !isIpMask(mask))
			return null;
		String[] maskBinary = getIpBinary(mask);
		String[] ipBinary = getIpBinary(ip);
		byte[] maskArr = toBinary(maskBinary);
		byte[] ipArr = toBinary(ipBinary);
		int maskLen = 0;
		for (int i = 0; i < maskArr.length; i++)
			maskLen += maskArr[i];
		int hostNumberLen = 32 - maskLen;
		int maxHost = 1 << hostNumberLen;
		byte[] mod = new byte[32];
		for (int i = 0; i < 32; i++)
			mod[i] = (byte) (maskArr[i] & ipArr[i]);
		List<String> ipList = new ArrayList<String>();
		StringBuilder genIp = new StringBuilder();
		for (int i = 0; i < maxHost; i++) {
			int decimal = 0;
			for (int j = 0; j < 32; j++) {
				decimal += mod[j] << (7 - j % 8);
				if (j != 0 && (j + 1) % 8 == 0) {
					if (genIp.length() == 0)
						genIp.append(decimal);
					else
						genIp.append(".").append(decimal);
					decimal = 0;
				}
			}
			binaryArrayPlus(mod, 1);
			String generateIp = genIp.toString();
			genIp.delete(0, genIp.length());
			if (ignoreFirstAndLastIp && (i == 0 || i == maxHost - 1))
				continue;
			if (!containParamIp && generateIp.equals(ip))
				continue;
			ipList.add(generateIp);
		}
		return ipList;
	}

	/**
	 * Get Mask from network prefix
	 * 
	 * @param prefix
	 * @return
	 */
	private static String getMask(int prefix) {
		if (prefix > 32) // Adjust invalid prefix
			prefix = 32;
		else if (prefix < 0)
			prefix = 0;
		// Convert prefix to binary numeric string
		String binary = String.format("%0" + prefix + "d", 0).replace("0", "1")
				+ String.format("%0" + (32 - prefix) + "d", 0);
		// Divide the binary numeric string into 4 equal parts, then convert to decimal
		// and merge them
		return Integer.valueOf(binary.substring(0, 8), 2) + "." + Integer.valueOf(binary.substring(8, 16), 2) + "."
				+ Integer.valueOf(binary.substring(16, 24), 2) + "." + Integer.valueOf(binary.substring(24, 32), 2);
	}

	/**
	 * Get the valid IPv4 address on the current node and all addresses within the
	 * same subnet
	 * 
	 * @return
	 * @throws SocketException
	 */
	public static LinkedHashMap<String, List<String>> getV4InetAddrs() throws SocketException {
		LinkedHashMap<String, List<String>> mapAddrs = new LinkedHashMap<String, List<String>>();
		// For all local network interfaces
		for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
			// Eliminate loopback interfaces and inactive network interfaces
			if ((!nic.isLoopback()) && nic.isUp()) {
				// Get all network addresses of the current interface
				for (InterfaceAddress infAddr : nic.getInterfaceAddresses()) {
					// Only keep IPv4 addresses
					if (infAddr.getAddress() instanceof Inet4Address) {
						String addr = infAddr.getAddress().getHostAddress();
						String mask = getMask(infAddr.getNetworkPrefixLength());
						mapAddrs.put(addr, getLocalAreaIpList(addr, mask, true));
					}
				}
			}
		}
		logger.info(JSONObject.toJSONString(mapAddrs));
		return mapAddrs;
	}

	/**
	 * Check whether the source address and destination address belong to the same
	 * subnet, the subnet list can only be obtained from the current node
	 * 
	 * @param srcAddr
	 * @param dstAddr
	 * @param mapAddrs
	 * @return
	 */
	public static boolean isSameSubnet(String srcAddr, String dstAddr, LinkedHashMap<String, List<String>> mapAddrs) {
		if (dstAddr.equals("134.80.19.90")) {
			System.out.println("captured!");
		}
		Iterator<String> itrKey = mapAddrs.keySet().iterator();
		while (itrKey.hasNext()) {
			List<String> ipList = mapAddrs.get(itrKey.next());
			if (ipList.contains(srcAddr) && ipList.contains(dstAddr))
				return true;
		}
		return false;
	}

	/**
	 * Get System Serial Number
	 * 
	 * @return
	 */
	public static String getSerNum() {
		String[] command = { "dmidecode -s system-serial-number" };
		String sNum = null;
		try {
			Process SerNumProcess = Runtime.getRuntime().exec(command);
			BufferedReader sNumReader = new BufferedReader(new InputStreamReader(SerNumProcess.getInputStream()));
			sNum = sNumReader.readLine().trim();
			SerNumProcess.waitFor();
			sNumReader.close();
		} catch (Exception ex) {
			sNum = "unavailable";
		}
		return sNum;
	}

	public static void main(String[] args) {
//		while (true) {
//			Thread.sleep(500);
//			System.out.println(isOpen("134.80.184.25", 8998));
//		}
		if (args.length == 0 || args[0].equals("-h") || args[0].equals("--h")) {
			logger.info("Usage: PortSniffer <host> <mask> <port>");
			logger.info("Usage: PortSniffer <host> <mask> <portrange>");
			logger.info("Usage: PortSniffer <host> <mask> <portlist>");
			logger.info("Example: PortSniffer 192.168.0.1 255.255.255.0 21");
			logger.info("Example: PortSniffer 192.168.0.1 255.255.255.0 21-29");
			logger.info("Example: PortSniffer 192.168.0.1 255.255.255.0 21,23,29");
		}
		List<String> ips = getLocalAreaIpList(args[0], args[1], true);
//		List<String> ips = getLocalAreaIpList("134.80.132.189", "255.255.255.0", true);
		for (String ip : ips) {
			logger.info(ip + "'s port " + args[2] + " opened : " + isOpen(ip, Integer.parseInt(args[2])));
		}
	}
}

package org.ayakaji;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

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

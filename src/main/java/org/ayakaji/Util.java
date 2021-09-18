/*****************************
 * Local listening collector *
 ****************************/
// Usage
// java -Djava.library.path=.\src\main\native -jar prjPrismSniff-0.0.1-SNAPSHOT.jar
package org.ayakaji;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.hyperic.sigar.NetConnection;
import org.hyperic.sigar.NetFlags;
import org.hyperic.sigar.Sigar;
import org.hyperic.sigar.SigarException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import com.alibaba.fastjson.JSONObject;

public class Util {
	private final static Logger logger = Logger.getLogger(Util.class.getName());
	public static List<LinkedHashMap<String, String>> listeners = new ArrayList<LinkedHashMap<String, String>>();
	public static List<String> localAddresses = new ArrayList<String>();
	private static boolean IPv6_Support = false;

	/**
	 * Use Sigar to get all listeners. For a listener that listens to any
	 * destination address, such as 0.0.0.0:80, the convergence conversion should be
	 * performed according to the local address table to match the packet session.
	 * Agreement: localAddress/localPort stands for monitoring side or server side,
	 * and remoteAddress/remotePort stands for business initiator or client side
	 * 
	 * @param args
	 * @throws SigarException
	 */
	public static void getListeners() throws SigarException {
		listeners.clear();
		Sigar sigar = new Sigar();
		NetConnection[] ncs = sigar.getNetConnectionList(NetFlags.TCP_LISTEN | NetFlags.CONN_TCP | NetFlags.CONN_UDP);
		for (NetConnection nc : ncs) {
			if (nc.getLocalAddress().equals("0.0.0.0") || nc.getLocalAddress().equals("::")
					|| nc.getLocalAddress().equals("::1")) { // address split
				for (String localAddress : localAddresses) {
					LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
					map.put("localAddress", localAddress);
					map.put("localPort", Long.toString(nc.getLocalPort()));
					map.put("proto", nc.getTypeString());
					map.put("remoteAddress", nc.getRemoteAddress().replace("::", "0.0.0.0"));
					map.put("remotePort", Long.toString(nc.getRemotePort()));
					listeners.add(map);
				}
			} else {
				LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
				map.put("localAddress", nc.getLocalAddress());
				map.put("localPort", Long.toString(nc.getLocalPort()));
				map.put("proto", nc.getTypeString());
				map.put("remoteAddress", nc.getRemoteAddress().replace("\\:\\:", "0.0.0.0"));
				map.put("remotePort", Long.toString(nc.getRemotePort()));
				listeners.add(map);
			}

		}
		logger.info("Found " + ncs.length + " listening address/ports!");
		logger.info(JSONObject.toJSONString(listeners, true));
	}

	/**
	 * Get all available interface addresses. The purpose is to know which address
	 * ports are actually in the listening state. For example, the listener is
	 * defined as 0.0.0.0:80. If the interface addresses are 192.168.0.1 and
	 * 10.245.0.1, the listening address that can actually provide services is
	 * 192.168.0.1:80 And 10.245.0.1:80, and match it to the Packets message, the
	 * session with the same listening address can be converged: For example,
	 * 192.168.0.3:[51000~65535] can be converged to 192.168.0.3:0 when accessing
	 * 192.168.0.1:80, then the packet session in the policy restoration is
	 * converged.
	 * 
	 * @throws PcapNativeException
	 */
	public static void getLocalAddresses() throws PcapNativeException {
		localAddresses.clear();
		List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
		for (PcapNetworkInterface pni : allDevs) {
			for (PcapAddress pa : pni.getAddresses()) {
				InetAddress ia = pa.getAddress();
				if (ia instanceof Inet4Address) {
					localAddresses.add(ia.getHostAddress());
				}
				if (ia instanceof Inet6Address && IPv6_Support) {
					localAddresses.add(ia.getHostAddress());
				}
			}
		}
		logger.info("All available interface addresses: " + localAddresses.toString());
	}

	/**
	 * Use IP address or interface's name to locate network interface
	 * 
	 * @param id
	 * @return
	 * @throws PcapNativeException
	 */
	public static PcapNetworkInterface getNetworkInterface(String ipOrName) throws PcapNativeException {
		List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
		for (PcapNetworkInterface pni : allDevs) {
			for (PcapAddress pa : pni.getAddresses()) {
				InetAddress ia = pa.getAddress();
				if (ia instanceof Inet4Address && ia.getHostAddress().equals(ipOrName)
						|| ia instanceof Inet6Address && IPv6_Support && ia.getHostAddress().equals(ipOrName)) {
					logger.info("A matching network interface has been found.");
					return pni;
				}
			}
			if (pni.getName().equals(ipOrName)) {
				logger.info("A matching network interface has been found.");
				return pni;
			}
		}
		logger.info("No matching network interface found.");
		return null;
	}

	public static boolean isLinux() {
		return System.getProperty("os.name").toLowerCase().contains("linux");
	}

	public static boolean isWindows() {
		return System.getProperty("os.name").toLowerCase().contains("windows");
	}

	public static boolean isOpen(String host, String port) {
		Socket sock = new Socket();
		try {
			sock.connect(new InetSocketAddress(host, Integer.parseInt(port)), 1000);
			sock.setSoTimeout(1000);
			sock.close();
			sock = null;
			return true;
		} catch (IOException e) {
			sock = null;
			return false;
		}
	}
	
	public static boolean isInteger(String str) {
		Pattern pattern = Pattern.compile("^[-\\+]?[\\d]*$");
		return pattern.matcher(str).matches();
	}

	/**
	 * Pay attention to get all interface addresses first, and get all listening
	 * addresses last. The order cannot be reversed.
	 * 
	 * @param args
	 * @throws SigarException
	 * @throws PcapNativeException
	 */
	public static void main(String[] args) throws SigarException, PcapNativeException {
		getLocalAddresses();
		getListeners();
		getNetworkInterface("134.80.19.88");
	}

}

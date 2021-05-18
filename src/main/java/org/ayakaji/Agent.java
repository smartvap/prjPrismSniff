/*************************************
 * Network Strategy Recovery Project *
 * Bug1. If the local firewall is    *
 * turned on, the packets whose      *
 * connection is rejected cannot be  *
 * distinguished. These packets are  *
 * network policies that cannot be   *
 * regarded as allowed.              *
 ************************************/
package org.ayakaji;

import java.io.IOException;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.hyperic.sigar.SigarException;
import org.joda.time.DateTime;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import com.alibaba.fastjson.JSONObject;

public final class Agent implements Runnable {
	private final static Logger logger = Logger.getLogger(Agent.class.getName());
	private final static List<Agent> agentList = new ArrayList<Agent>(); // all agents
	private final static int snapLen = 65536; // 64kB
	private final static int timeout = 50; // 50ms
//	private final static int bufSz = 1048576; // 1mB
	private final static String filter = "tcp or udp"; // default filter

	private Thread thread = null;
	private String threadName = null;
	private PcapNetworkInterface pni = null;
	private List<LinkedHashMap<String, String>> connTbl = new ArrayList<LinkedHashMap<String, String>>();

	public Agent(String name, PcapNetworkInterface pni) {
		this.threadName = "Sniffer-" + name;
		this.pni = pni;
	}

	/**
	 * Collect data packets into the connection table after filtering, converging,
	 * and removing duplicates. Agreement: srcAddr/srcPort stands for client side,
	 * and dstAddr/dstPort stands for server side
	 * 
	 * @param pkt
	 */
	private void collect(Map<String, String> pkt) {
		// Try to match with connection table.
		// The following two cases are equivalent:
		// <client ip>:0 <tcp> <server ip>:<listening port>
		// <server ip>:<listening port> <tcp> <client ip>:0
		for (LinkedHashMap<String, String> map : connTbl) {
			if (map.get("dstAddr").equals(pkt.get("srcAddr")) && map.get("dstPort").equals(pkt.get("srcPort"))
					&& map.get("srcAddr").equals(pkt.get("dstAddr")) && map.get("srcPort").equals("0")
					&& map.get("proto").equals(pkt.get("proto"))) {
				return;
			} else if (map.get("dstAddr").equals(pkt.get("dstAddr")) && map.get("dstPort").equals(pkt.get("dstPort"))
					&& map.get("srcAddr").equals(pkt.get("srcAddr")) && map.get("srcPort").equals("0")
					&& map.get("proto").equals(pkt.get("proto"))) {
				return;
			}
		}
		// If not match, then find the listener side
		// Bug: Currently, there is no consideration of limiting the remote IP and
		// remote port
		boolean localAccess = false;
		for (LinkedHashMap<String, String> listener : Util.listeners) {
			if (listener.get("localAddress").equals(pkt.get("srcAddr"))
					&& listener.get("localPort").equals(pkt.get("srcPort"))
					&& listener.get("proto").equals(pkt.get("proto"))) {
				if (listener.get("remoteAddress").equals("0.0.0.0") && listener.get("remotePort").equals("0")) {
					LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
					map.put("srcAddr", pkt.get("dstAddr"));
					map.put("srcPort", "0");
					map.put("proto", pkt.get("proto"));
					map.put("dstAddr", pkt.get("srcAddr"));
					map.put("dstPort", pkt.get("srcPort"));
					connTbl.add(map);
					localAccess = true;
				}
			} else if (listener.get("localAddress").equals(pkt.get("dstAddr"))
					&& listener.get("localPort").equals(pkt.get("dstPort"))
					&& listener.get("proto").equals(pkt.get("proto"))) {
				if (listener.get("remoteAddress").equals("0.0.0.0") && listener.get("remotePort").equals("0")) {
					LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
					map.put("srcAddr", pkt.get("srcAddr"));
					map.put("srcPort", "0");
					map.put("proto", pkt.get("proto"));
					map.put("dstAddr", pkt.get("dstAddr"));
					map.put("dstPort", pkt.get("dstPort"));
					connTbl.add(map);
					localAccess = true;
				}
			}
		}
		if (!localAccess) {
			LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
			map.put("srcAddr", pkt.get("srcAddr"));
			map.put("srcPort", pkt.get("srcPort"));
			map.put("proto", pkt.get("proto"));
			map.put("dstAddr", pkt.get("dstAddr"));
			map.put("dstPort", pkt.get("dstPort"));
			connTbl.add(map);
		}
	}

	private void dump() {
		String json = JSONObject.toJSONString(connTbl, true);
		String appPath = System.getProperty("user.dir");
		Path dmpPath = Paths.get(appPath, "conn-" + DateTime.now().toString("YYYYMMDDhh24mmss") + ".json");
		if (!Files.exists(dmpPath)) {
			try {
				Files.createFile(dmpPath);
			} catch (IOException e) {
				logger.warning(e.getMessage());
				logger.warning("Cannot dump connection table!");
				return;
			}
		}
		try {
			Files.write(dmpPath, json.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
		} catch (IOException e) {
			logger.warning(e.getMessage());
			logger.warning("Cannot dump connection table!");
			return;
		}
	}

	@Override
	public void run() {
		logger.info("Started " + threadName);
		PcapHandle hnd = null;
		try {
			hnd = pni.openLive(snapLen, PromiscuousMode.PROMISCUOUS, timeout);
		} catch (PcapNativeException e) {
			hnd = null;
			pni = null;
			logger.severe(e.getMessage());
			logger.severe("Cannot start a new capture.");
			return;
		}
		if (hnd == null) {
			logger.severe("Cannot start a new capture.");
			return;
		}
		try {
			hnd.setFilter(filter, BpfCompileMode.OPTIMIZE);
		} catch (PcapNativeException e) {
			hnd.close();
			hnd = null;
			pni = null;
			logger.severe(e.getMessage());
			logger.severe("Cannot set filter.");
			return;
		} catch (NotOpenException e) {
			hnd.close();
			hnd = null;
			pni = null;
			logger.severe(e.getMessage());
			logger.severe("Cannot set filter.");
			return;
		}
		try {
			hnd.loop(-1, new PacketListener() {

				@Override
				public void gotPacket(Packet packet) {
					LinkedHashMap<String, String> map = new LinkedHashMap<String, String>() {
						private static final long serialVersionUID = 1L;
						{
							put("srcAddr", "");
							put("srcPort", "");
							put("proto", "");
							put("dstAddr", "");
							put("dstPort", "");
						}
					};

					IpV4Packet ipv4Pkt = packet.get(IpV4Packet.class);
					if (ipv4Pkt == null) {
						logger.warning("Violating the rules, TCP or UDP packets must be IP packets!");
						return;
					}
					IpV4Header ipv4Hdr = ipv4Pkt.getHeader();
					if (ipv4Hdr == null) {
						logger.warning("Violating the rules, IP packet must have a header!");
						return;
					}
					Inet4Address srcAddr = ipv4Hdr.getSrcAddr();
					if (srcAddr == null) {
						logger.warning("Violating the rules, IP packet header must have a source address!");
					}
					map.put("srcAddr", srcAddr.getHostAddress());
					Inet4Address dstAddr = ipv4Hdr.getDstAddr();
					if (dstAddr == null) {
						logger.warning("Violating the rules, IP packet header must have a destination address!");
						return;
					}
					map.put("dstAddr", dstAddr.getHostAddress());
					TcpPacket tcpPkt = packet.get(TcpPacket.class);
					if (tcpPkt != null) { // This must be a TCP packet
						map.put("proto", "tcp");
						TcpHeader tcpHdr = tcpPkt.getHeader();
						if (tcpHdr == null) {
							logger.warning("Violating the rules, TCP packet must have a header.");
							return;
						}
						TcpPort srcPort = tcpHdr.getSrcPort();
						if (srcPort == null) {
							logger.warning("Violating the rules, TCP packet header must have a source port.");
							return;
						}
						map.put("srcPort", srcPort.valueAsString());
						TcpPort dstPort = tcpHdr.getDstPort();
						if (dstPort == null) {
							logger.warning("Violating the rules, TCP packet header must have a destination port.");
							return;
						}
						map.put("dstPort", dstPort.valueAsString());
					} else {
						UdpPacket udpPkt = packet.get(UdpPacket.class);
						if (udpPkt != null) { // This must be a UDP packet
							map.put("proto", "udp");
							UdpHeader udpHdr = udpPkt.getHeader();
							if (udpHdr == null) {
								logger.warning("Violating the rules, UDP packet must have a header.");
								return;
							}
							UdpPort srcPort = udpHdr.getSrcPort();
							if (srcPort == null) {
								logger.warning("Violating the rules, UDP packet header must have a source port.");
								return;
							}
							map.put("srcPort", srcPort.valueAsString());
							UdpPort dstPort = udpHdr.getDstPort();
							if (dstPort == null) {
								logger.warning("Violating the rules, UDP packet header must have a destination port.");
								return;
							}
							map.put("dstPort", dstPort.valueAsString());
						}
					}
					collect(map); // Try to collect this packet
				}
			});
		} catch (PcapNativeException e) {
			logger.severe(e.getMessage());
			hnd = null;
			pni = null;
			logger.severe("Abnormal ended " + threadName);
			return;
		} catch (InterruptedException e) {
			logger.severe(e.getMessage());
			hnd = null;
			pni = null;
			logger.severe("Abnormal ended " + threadName);
			return;
		} catch (NotOpenException e) {
			logger.severe(e.getMessage());
			hnd = null;
			pni = null;
			logger.severe("Abnormal ended " + threadName);
			return;
		}
		hnd.close();
		logger.info("Ended " + threadName);
	}

	public void start() {
		if (thread == null) {
			thread = new Thread(this, threadName);
			thread.start();
		}
	}

	public static void main(String[] args)
			throws PcapNativeException, InterruptedException, NotOpenException, SigarException {
		Util.getLocalAddresses();
		Util.getListeners();
		List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
		boolean fAny = false;
		for (PcapNetworkInterface pni : allDevs) {
			if (pni.getName().equals("any")) { // Usually Linux operating system has pseudo device any
				Agent agent = new Agent(pni.getName(), pni);
				agent.start();
				fAny = true;
				agentList.add(agent);
				break;
			}
		}
		if (!fAny) { // if there is no interface named any
			for (PcapNetworkInterface pni : allDevs) {
				Agent agent = new Agent(pni.getName(), pni);
				agent.start();
				agentList.add(agent);
			}
		}
		while (true) {
			Thread.sleep(30000);
			for (Agent agt : agentList) {
				agt.dump();
			}
		}
	}
}

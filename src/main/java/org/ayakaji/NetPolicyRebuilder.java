package org.ayakaji;

import java.io.IOException;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.logging.Logger;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
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

public class NetPolicyRebuilder implements Runnable {
	private final static Logger logger = Logger.getLogger(NetPolicyRebuilder.class.getName());
	private final static String hsqlDriver = "org.hsqldb.jdbcDriver";
	private final static String hsqlUrl = "jdbc:hsqldb:mem:prism";
	private final static String hsqlUser = "sa";
	private final static String hsqlPass = "";
	private static Connection conn = null;
	private Thread thread = null;
	private final static int STATUS_ERR = 0; // match result status
	private final static int STATUS_MATCH_INIT = 1; // exactly match with initial strategy
	private final static int STATUS_PART_INIT = 2; // partialy match with initial strategy
	private final static int STATUS_MATCH_CONV = 3; // match with convergent strategy
	private final static int STATUS_INIT_STRATEGY = 4; // new strategy
	private final static String filter = "not net 10.233.0.0/18 and not net 10.222.64.0/18 and not net 224.0.0.0/24 and not ( ip[20+12:1]=10 and ip[20+13:1]=222 and ip[20+16:1]=10 and ip[20+17:1]=222 ) and not host 255.255.255.255 and not host 127.0.0.1 and not arp and not icmp and not icmp6";

	/**
	 * Database initialization
	 * 
	 * @throws ClassNotFoundException
	 * @throws SQLException
	 */
	private static void initDB() throws ClassNotFoundException, SQLException {
		Class.forName(hsqlDriver);
		conn = DriverManager.getConnection(hsqlUrl, hsqlUser, hsqlPass);
		conn.setAutoCommit(true);
		Statement stmt = conn.createStatement();
		// @formatter:off
		stmt.execute(""
				+ "create table network_policy("
				+ "  src_addr varchar not null, "
				+ "  src_port varchar not null, "
				+ "  proto varchar not null, "
				+ "  dst_addr varchar not null, "
				+ "  dst_port varchar not null"
				+ ")");
		stmt.execute(""
				+ "create index idx on network_policy("
				+ "  src_addr, src_port, proto, dst_addr, dst_port"
				+ ")");
		// @formatter:on
		stmt.close();
		stmt = null;
		logger.info("HSQL initialized successfully!");
	}

	/**
	 * Packet capture core
	 * 
	 * @throws PcapNativeException
	 * @throws NotOpenException
	 * @throws InterruptedException
	 */
	private static void capure() throws PcapNativeException, NotOpenException, InterruptedException {
		PcapNetworkInterface pni = null;
		if (Util.isLinux()) {
			pni = Util.getNetworkInterface("any");
			if (pni == null)
				return;
		} else if (Util.isWindows()) {
			if (Util.localAddresses.size() == 0)
				Util.getLocalAddresses();
			if (Util.localAddresses.size() == 0)
				return;
			pni = Util.getNetworkInterface(Util.localAddresses.get(0));
			if (pni == null)
				return;
		} else {
			logger.warning("Could not find any eligible network interface!");
		}
		PcapHandle ph = pni.openLive(65536, PromiscuousMode.PROMISCUOUS, 50);
		ph.setFilter(filter, BpfCompileMode.OPTIMIZE);
		ph.loop(-1, new PacketListener() {
			@Override
			public void gotPacket(Packet packet) {
				IpV4Packet ipv4Pkt = packet.get(IpV4Packet.class);
				if (ipv4Pkt == null)
					return;
				IpV4Header ipv4Hdr = ipv4Pkt.getHeader();
				if (ipv4Hdr == null)
					return;
				Inet4Address ipv4SrcAddr = ipv4Hdr.getSrcAddr();
				if (ipv4SrcAddr == null)
					return;
				String srcAddr = ipv4SrcAddr.getHostAddress();
				if (srcAddr == null || srcAddr.equals(""))
					return;
				Inet4Address ipv4DstAddr = ipv4Hdr.getDstAddr();
				if (ipv4DstAddr == null)
					return;
				String dstAddr = ipv4DstAddr.getHostAddress();
				if (dstAddr == null || dstAddr.equals(""))
					return;
				String proto = null;
				String srcPort = null;
				String dstPort = null;
				TcpPacket tcpPkt = packet.get(TcpPacket.class);
				if (tcpPkt != null) {
					proto = "tcp";
					TcpHeader tcpHdr = tcpPkt.getHeader();
					if (tcpHdr == null)
						return;
					TcpPort tcpSrcPort = tcpHdr.getSrcPort();
					if (tcpSrcPort == null)
						return;
					srcPort = tcpSrcPort.valueAsString();
					if (srcPort == null || srcPort.equals(""))
						return;
					TcpPort tcpDstPort = tcpHdr.getDstPort();
					if (tcpDstPort == null)
						return;
					dstPort = tcpDstPort.valueAsString();
					if (dstPort == null || dstPort.equals(""))
						return;
					analyze(srcAddr, srcPort, proto, dstAddr, dstPort);
					return;
				}
				UdpPacket udpPkt = packet.get(UdpPacket.class);
				if (udpPkt != null) {
					proto = "udp";
					UdpHeader udpHdr = udpPkt.getHeader();
					if (udpHdr == null)
						return;
					UdpPort udpSrcPort = udpHdr.getSrcPort();
					if (udpSrcPort == null)
						return;
					srcPort = udpSrcPort.valueAsString();
					if (srcPort == null || srcPort.equals(""))
						return;
					UdpPort udpDstPort = udpHdr.getDstPort();
					if (udpDstPort == null)
						return;
					dstPort = udpDstPort.valueAsString();
					if (dstPort == null || dstPort.equals(""))
						return;
					analyze(srcAddr, srcPort, proto, dstAddr, dstPort);
					return;
				}
			}
		});
		ph.close();
	}

	// @formatter:off
	/**
	 * Packet analyzing workflow:
	 *  1. Try to match with existing strategy
	 *     Note: Strategies are usually divided into initial strategies and convergence strategies, 
	 *     The difference between the above two types of strategies is that the source port of the 
	 *     former is determined, which is suitable for two-way communication scenarios, and the 
	 *     source port of the latter is converged to 0, which is suitable for the scenario of 
	 *     random allocation of source ports.
	 *  2. If it exactly matches one initial strategy, including the source port, there will be two 
	 *     situations. The packet and the packet converted into the initial strategy belong to the 
	 *     same session, or the protocol is indeed a two-way communication mode. In either case, 
	 *     there is no need to deal with it, just discard the packet.
	 *  3. If only the source port does not match the initial policy, all other parts matched. It 
	 *     means that it was not a two-way communication, and the initial strategy will be 
	 *     converted to a convergence strategy, that is, modify the database record corresponding 
	 *     to the initial strategy and update the source port to 0
	 *  4. If it matches with convergency strategy, then discard this packet directly
	 *  5. If not, then use sniffer to check which side is server side
	 *  6. Normalize this packet in <client-ip>:<client-port>:<tcp|udp>:<server-ip>:<server-port> 
	 *     format as initialized strategy
	 *  7. Write this initialized strategy into database
	 * @param srcAddr
	 * @param srcPort
	 * @param proto
	 * @param dstAddr
	 * @param dstPort
	 * @throws SQLException 
	 */
	// @formatter:on
	private static void analyze(String srcAddr, String srcPort, String proto, String dstAddr, String dstPort) {
		int status = STATUS_ERR;
		boolean bSwap = false; // Whether the order of the initiator and the receiver is reversed
		try {
			status = match(srcAddr, srcPort, proto, dstAddr, dstPort);
			if (status == STATUS_INIT_STRATEGY) { // If not match, then try to change the order
				status = match(dstAddr, dstPort, proto, srcAddr, srcPort);
				bSwap = true; // reversed
			}
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		if (status == STATUS_MATCH_INIT || status == STATUS_MATCH_CONV) {
			;
		} else if (status == STATUS_PART_INIT) {
			try {
				if (bSwap) {
					converge(dstAddr, dstPort, proto, srcAddr, srcPort);
				} else {
					converge(srcAddr, srcPort, proto, dstAddr, dstPort);
				}
			} catch (SQLException e) {
				logger.warning(e.getMessage());
			}
		} else if (status == STATUS_INIT_STRATEGY) {
			if (Util.isOpen(srcAddr, srcPort)) {
				try {
					append(dstAddr, dstPort, proto, srcAddr, srcPort);
				} catch (SQLException e) {
					logger.warning(e.getMessage());
				}
			} else if (Util.isOpen(dstAddr, dstPort)) {
				try {
					append(srcAddr, srcPort, proto, dstAddr, dstPort);
				} catch (SQLException e) {
					logger.warning(e.getMessage());
				}
			}
		}
	}

	/**
	 * Execution strategy convergence
	 * 
	 * @param srcAddr
	 * @param srcPort
	 * @param proto
	 * @param dstAddr
	 * @param dstPort
	 * @throws SQLException
	 */
	private static void converge(String srcAddr, String srcPort, String proto, String dstAddr, String dstPort)
			throws SQLException {
		if (conn == null || conn.isClosed()) {
			logger.warning("Database connection is unavailable!");
			return;
		}
		// @formatter:off
		PreparedStatement pstmt = conn.prepareStatement(
				"update network_policy set src_port = '0' "
				+ "where src_addr=? and proto=? and "
				+ "dst_addr=? and dst_port=?");
		// @formatter:on
		pstmt.setString(1, srcAddr);
		pstmt.setString(2, proto);
		pstmt.setString(3, dstAddr);
		pstmt.setString(4, dstPort);
		int rs = pstmt.executeUpdate();
		if (rs == 1) {
			logger.info("Updated successfully! " + "[" + srcAddr + ":0," + proto + "," + dstAddr + ":" + dstPort + "]");
		}
	}

	private static void append(String srcAddr, String srcPort, String proto, String dstAddr, String dstPort)
			throws SQLException {
		if (conn == null || conn.isClosed()) {
			logger.warning("Database connection is unavailable!");
			return;
		}
		// @formatter:off
		PreparedStatement pstmt = conn.prepareStatement(
				"insert into network_policy(src_addr, "
				+ "src_port, proto, dst_addr, dst_port) "
				+ "values (?, ?, ?, ?, ?)");
		// @formatter:on
		pstmt.setString(1, srcAddr);
		pstmt.setString(2, srcPort);
		pstmt.setString(3, proto);
		pstmt.setString(4, dstAddr);
		pstmt.setString(5, dstPort);
		int rs = pstmt.executeUpdate();
		if (rs == 1) {
			logger.info("Updated successfully! " + "[" + srcAddr + ":" + srcPort + "," + proto + "," + dstAddr + ":"
					+ dstPort + "]");
		}
	}

	/**
	 * Check whether it matches the existing strategy
	 * 
	 * @param srcAddr
	 * @param srcPort
	 * @param proto
	 * @param dstAddr
	 * @param dstPort
	 * @return
	 * @throws SQLException
	 */
	private static int match(String srcAddr, String srcPort, String proto, String dstAddr, String dstPort)
			throws SQLException {
		if (conn == null || conn.isClosed()) {
			logger.warning("Database connection is unavailable!");
			return STATUS_ERR;
		}
		// @formatter:off
		PreparedStatement pstmt = conn.prepareStatement(
				"select count(1) from network_policy "
				+ "where src_addr=? and src_port=? and "
				+ "proto=? and dst_addr=? and dst_port=?");
		// @formatter:on
		// Scene 1. If exactly match with the initial strategy
		pstmt.setString(1, srcAddr);
		pstmt.setString(2, srcPort);
		pstmt.setString(3, proto);
		pstmt.setString(4, dstAddr);
		pstmt.setString(5, dstPort);
		ResultSet rs = pstmt.executeQuery();
		while (rs.next()) {
			if (rs.getInt(1) > 0) {
				rs.close();
				rs = null;
				return STATUS_MATCH_INIT;
			}
		}
		rs.close();
		rs = null;
		pstmt.close();
		pstmt = null;

		// Scene 2. If partially match with the initial strategy
		// @formatter:off
		pstmt = conn.prepareStatement(
				"select count(1) from network_policy "
				+ "where src_addr=? and src_port<>'0' and "
				+ "src_port<>? and proto=? and dst_addr=? "
				+ "and dst_port=?");
		// @formatter:on
		pstmt.setString(1, srcAddr);
		pstmt.setString(2, srcPort);
		pstmt.setString(3, proto);
		pstmt.setString(4, dstAddr);
		pstmt.setString(5, dstPort);
		rs = pstmt.executeQuery();
		while (rs.next()) {
			if (rs.getInt(1) > 0) {
				rs.close();
				rs = null;
				return STATUS_PART_INIT;
			}
		}
		rs.close();
		rs = null;
		pstmt.close();
		pstmt = null;

		// Scene 3. If match with convergence strategy
		// @formatter:off
		pstmt = conn.prepareStatement(
				"select count(1) from network_policy "
				+ "where src_addr=? and src_port=? and "
				+ "proto=? and dst_addr=? and dst_port=?");
		// @formatter:on
		pstmt.setString(1, srcAddr);
		pstmt.setString(2, "0");
		pstmt.setString(3, proto);
		pstmt.setString(4, dstAddr);
		pstmt.setString(5, dstPort);
		rs = pstmt.executeQuery();
		while (rs.next()) {
			if (rs.getInt(1) > 0) {
				rs.close();
				rs = null;
				return STATUS_MATCH_CONV;
			}
		}
		rs.close();
		rs = null;
		pstmt.close();
		pstmt = null;

		// Scene 4. If it does not meet the above three situations, initialize a new
		// strategy
		return STATUS_INIT_STRATEGY;
	}

	private static void dump() throws SQLException {
		if (conn == null || conn.isClosed()) {
			logger.warning("Database connection is unavailable!");
			return;
		}
		String appPath = System.getProperty("user.dir");
		Path dmpPath = Paths.get(appPath, "policy.json");
		if (!Files.exists(dmpPath)) {
			try {
				Files.createFile(dmpPath);
			} catch (IOException e) {
				logger.warning(e.getMessage());
				logger.warning("Cannot dump connection table!");
				return;
			}
		}
		// @formatter:off
		PreparedStatement pstmt = conn.prepareStatement(
				"select src_addr, src_port, proto, dst_addr, "
				+ "dst_port from network_policy");
		// @formatter:on
		ResultSet rs = pstmt.executeQuery();
		List<LinkedHashMap<String, String>> list = new ArrayList<LinkedHashMap<String, String>>();
		while (rs.next()) {
			LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
			map.put("src_addr", rs.getString(1));
			map.put("src_port", rs.getString(2));
			map.put("proto", rs.getString(3));
			map.put("dst_addr", rs.getString(4));
			map.put("dst_port", rs.getString(5));
			list.add(map);
		}
		rs.close();
		rs = null;
		pstmt.close();
		pstmt = null;
		String json = JSONObject.toJSONString(list, true);
		try {
			Files.write(dmpPath, json.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
		} catch (IOException e) {
			logger.warning(e.getMessage());
			logger.warning("Cannot dump connection table!");
			return;
		}
	}

	public static void main(String[] args)
			throws ClassNotFoundException, SQLException, PcapNativeException, NotOpenException, InterruptedException {
		initDB();
		NetPolicyRebuilder npr = new NetPolicyRebuilder();
		npr.start();
		while (true) {
			Thread.sleep(60000);
			dump();
		}
	}

	public void start() {
		if (thread == null) {
			thread = new Thread(this, "main-1");
			thread.start();
		}
	}

	@Override
	public void run() {
		try {
			NetPolicyRebuilder.capure();
		} catch (PcapNativeException e) {
			logger.warning(e.getMessage());
		} catch (NotOpenException e) {
			logger.warning(e.getMessage());
		} catch (InterruptedException e) {
			logger.warning(e.getMessage());
		}
	}

}

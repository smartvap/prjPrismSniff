package org.ayakaji;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

public class DBUtils {
	private final static Logger logger = Logger.getLogger(DBUtils.class.getName());
	private static Connection conn = null;
	private final static String jsonPath = "C:\\Users\\heqiming\\Desktop\\policy";
	private final static int batchSize = 1000;

	private static void getConnection() {
		try {
			Class.forName("oracle.jdbc.driver.OracleDriver");
		} catch (ClassNotFoundException e) {
			logger.warning(e.getMessage());
			return;
		}
		try {
			conn = DriverManager.getConnection("jdbc:oracle:thin:@10.19.195.240:2521/orayy1", "tbcs", "tbcsbcv");
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
	}

	private static void initTbl() {
		Statement stmt = null;
		try {
			stmt = conn.createStatement();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		String sql = "CREATE TABLE strategy(" + "src_addr VARCHAR2(16), " + "src_port VARCHAR2(8), "
				+ "proto VARCHAR2(4), " + "dst_addr VARCHAR2(16), " + "dst_port VARCHAR2(8)" + ")";
		try {
			stmt.executeUpdate(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		try {
			stmt.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		logger.info("Success!");
	}

	private static void createIndex() {
		Statement stmt = null;
		try {
			stmt = conn.createStatement();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		String sql = "CREATE INDEX idx_strategy on strategy(src_addr, src_port, proto, dst_addr, dst_port)";
		try {
			stmt.executeUpdate(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		sql = "CREATE INDEX idx_strategy_dst on strategy(dst_addr, dst_port)";
		try {
			stmt.executeUpdate(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		try {
			stmt.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		logger.info("Success!");
	}

	private static void load() {
		File folder = new File(jsonPath);
		File[] files = folder.listFiles();
		for (File f : files) {
			if (!f.isDirectory()) {
				String json = null;
				try {
					json = FileUtils.readFileToString(f, "UTF-8");
				} catch (IOException e) {
					logger.warning(e.getMessage());
				}
				if (json == null || json.equals("")) {
					logger.warning("JSON Format is not valid!");
					return;
				}
				JSONArray jsonArr = JSONArray.parseArray(json);
				batchAppend(jsonArr);
			}
		}
	}

	/**
	 * Batch Append
	 * 
	 * @param arr
	 */
	private static void batchAppend(JSONArray arr) {
		String sql = "INSERT INTO strategy(src_addr, src_port, proto, dst_addr, dst_port) VALUES (?, ?, ?, ?, ?)";
		PreparedStatement ps = null;
		try {
			ps = conn.prepareStatement(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		for (int i = 0; i < arr.size(); i++) {
			JSONObject jsonObj = arr.getJSONObject(i);
			try {
				ps.setString(1, jsonObj.getString("src_addr"));
				ps.setString(2, jsonObj.getString("src_port"));
				ps.setString(3, jsonObj.getString("proto"));
				ps.setString(4, jsonObj.getString("dst_addr"));
				ps.setString(5, jsonObj.getString("dst_port"));
				ps.addBatch();
			} catch (SQLException e) {
				logger.warning(e.getMessage());
			}
			if (i % batchSize == 0) {
				try {
					ps.executeBatch();
				} catch (SQLException e) {
					logger.warning(e.getMessage());
				}
			}
		}
		try {
			ps.executeBatch();
			ps.close();
			conn.commit();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
	}

	private static void closeConnection() {
		if (conn == null)
			return;
		try {
			conn.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
	}

	/**
	 * Cleanup transient session strategy, Some sessions are temporary, such as
	 * passive sftp, the target will randomly generate some listening ports, these
	 * listening ports do not exist for a long time
	 */
	private static void cleanTransient() {
		// 1. Export all original strategy
		List<Map<String, String>> listDst = new ArrayList<Map<String, String>>();
		String sql = "SELECT /*+ parallel(t, 15)*/DISTINCT t.dst_addr, t.dst_port FROM strategy t";
		PreparedStatement ps = null;
		try {
			ps = conn.prepareStatement(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		ResultSet rs = null;
		try {
			rs = ps.executeQuery();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
		try {
			while (rs.next()) {
				Map<String, String> map = new HashMap<String, String>();
				map.put("dst_addr", rs.getString(1));
				map.put("dst_port", rs.getString(2));
				listDst.add(map);
			}
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
		try {
			rs.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
		rs = null;
		try {
			ps.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
		ps = null;
		logger.info("Count: " + listDst.size());

		// 2. Sniff the destination address & port, then delete the not opened ports
		sql = "DELETE FROM strategy t WHERE t.dst_addr = ? AND t.dst_port = ?";
		try {
			ps = conn.prepareStatement(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		for (Map<String, String> map : listDst) {
			if (!Util.isOpen(map.get("dst_addr"), map.get("dst_port"))) {
				try {
					ps.setString(1, map.get("dst_addr"));
					ps.setString(2, map.get("dst_port"));
					ps.executeUpdate();
				} catch (SQLException e) {
					logger.warning(e.getMessage());
				}
			}
		}

		try {
			conn.commit();
			ps.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
		ps = null;
	}

	private static void cleanInternalVisits() {
		String sql = "DELETE FROM strategy t WHERE t.src_addr BETWEEN "
				+ "'134.80.184.11' AND '134.80.184.50' AND t.dst_addr "
				+ "BETWEEN '134.80.184.11' AND '134.80.184.50'";
		PreparedStatement ps = null;
		try {
			ps = conn.prepareStatement(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		try {
			ps.executeUpdate();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
	}

	public static void extern_load() {
		getConnection();
		initTbl();
		createIndex();
		load();
		closeConnection();
	}

	public static void extern_clean_transient() {
		getConnection();
		cleanTransient();
		closeConnection();
	}

	public static void extern_clean_internal_visits() {
		getConnection();
		cleanInternalVisits();
		closeConnection();
	}

	public static void main(String[] args) {
		;
	}

}

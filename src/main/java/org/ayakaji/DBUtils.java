package org.ayakaji;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

public class DBUtils {
	private final static Logger logger = Logger.getLogger(DBUtils.class.getName()); // logger
	private final static String jsonDir = "."; // Default directory for json files is current folder
	private final static int batchSize = 1000; // Data entry for one-time import
	private final static String jdbcDrv = "oracle.jdbc.driver.OracleDriver"; // jdbc driver
	private final static String jdbcUrl = "jdbc:oracle:thin:@10.19.195.240:2521/orayy1"; // jdbc url
	private final static String jdbcUsr = "tbcs"; // username for account
	private final static String jdbcPsw = "tbcsbcv"; // password for account
	// the temporary table init sql template
	private final static String initSql = "CREATE TABLE _table_name_(" + "src_addr VARCHAR2(16), "
			+ "src_port VARCHAR2(8), " + "proto VARCHAR2(4), " + "dst_addr VARCHAR2(16), " + "dst_port VARCHAR2(8)"
			+ ")";
	private final static String idx1Sql = "CREATE INDEX idx_1_table_name_ on _table_name_(src_addr, src_port, proto, dst_addr, dst_port)";
	private final static String idx2Sql = "CREATE INDEX idx_2_table_name_ on _table_name_(dst_addr, dst_port)";
	private final static String insertSql = "INSERT INTO _table_name_(src_addr, src_port, proto, dst_addr, dst_port) VALUES (?, ?, ?, ?, ?)";
	private final static String dropSql = "DROP TABLE _table_name_ PURGE";
	private final static String tblCntSql = "SELECT COUNT(1) FROM user_tables t WHERE t.table_name = ?";
	private final static String subRplc = "_table_name_"; // String to be replaced
	private final static FileFilter ff = new FileFilter() {
		@Override
		public boolean accept(File file) {
			String s = file.getName().toLowerCase();
			if (s.startsWith("plc_") && s.endsWith(".json")) {
				return true;
			}
			return false;
		}
	};

	private Connection conn = null; // One file, one connection
	private String tblName = ""; // One file, one table

	public DBUtils(String tbl) {
		if (tbl.length() > 20)
			tblName = tbl.substring(0, 20);
		else
			tblName = tbl;
	}

	private void getConnection() {
		try {
			Class.forName(jdbcDrv);
		} catch (ClassNotFoundException e) {
			logger.warning(e.getMessage());
			return;
		}
		if (conn != null) {
			logger.warning("Connection has already been initialized!");
			return;
		}
		try {
			conn = DriverManager.getConnection(jdbcUrl, jdbcUsr, jdbcPsw);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			System.exit(0);
		}
	}

	private void initTbl() {
		Statement stmt = null;
		try {
			stmt = conn.createStatement();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		String sql = initSql.replaceAll(subRplc, tblName);
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
		logger.info("Init table success!");
	}

	private void createIndex() {
		Statement stmt = null;
		try {
			stmt = conn.createStatement();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		String sql = idx1Sql.replaceAll(subRplc, tblName);
		try {
			stmt.executeUpdate(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		sql = idx2Sql.replaceAll(subRplc, tblName);
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
		logger.info("Init index success!");
	}

	private void batchAppend(JSONArray arr) {
		String sql = insertSql.replaceAll(subRplc, tblName);
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
			logger.info("Data imported successfully!");
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
	}

	private void closeConnection() {
		if (conn == null)
			return;
		try {
			conn.close();
		} catch (SQLException e) {
			logger.warning(e.getMessage());
		}
	}

	/**
	 * Reset the table
	 */
	private void reset() {
		String sql = dropSql.replaceAll(subRplc, tblName);
		PreparedStatement ps = null;
		try {
			ps = conn.prepareStatement(sql);
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
		try {
			ps.executeUpdate();
			logger.info("Original Table has been dropped!");
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return;
		}
	}

	private boolean tblExists() {
		String sql = tblCntSql;
		PreparedStatement ps = null;
		try {
			ps = conn.prepareStatement(sql);
			ps.setString(1, tblName.toUpperCase());
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return false;
		}
		ResultSet rs = null;
		int cnt = 0;
		try {
			rs = ps.executeQuery();
			if (rs != null && rs.next())
				cnt = rs.getInt(1);
			if (cnt > 0) {
				logger.info("Table already exists!");
				return true;
			} else
				return false;
		} catch (SQLException e) {
			logger.warning(e.getMessage());
			return false;
		}
	}

	public void unload(JSONArray jsonArr) {
		getConnection();
		if (tblExists())
			reset();
		initTbl();
		createIndex();
		batchAppend(jsonArr);
		closeConnection();
	}

	/**
	 * JSON unified unloading entrance
	 */
	private static void unload() {
		File folder = new File(jsonDir);
		File[] files = folder.listFiles(ff);
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
				String tbl = f.getName().split("\\.")[0]; // the target table name
				JSONArray jsonArr = JSONArray.parseArray(json); // policy data
				DBUtils dbUtil = new DBUtils(tbl);
				dbUtil.unload(jsonArr);
			}
		}
	}

	public static void main(String[] args) {
		unload();
	}
}

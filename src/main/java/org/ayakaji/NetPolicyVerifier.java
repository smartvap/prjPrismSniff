package org.ayakaji;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

// 1. read outbound policies into json array
// 2. write json array to json file
// 3. upload json file to paragon nodes (manual)
// 4. call the verifier procedure on paragon nodes
// 5. collect unreachable ports into json array
// 6. dump json array to json file
// 7. load json file into database

public class NetPolicyVerifier {
	
	private final static Logger logger = Logger.getLogger(NetPolicyVerifier.class.getName());

	public static void main(String[] args) {
		String appPath = System.getProperty("user.dir");
		Path oriPath = Paths.get(appPath, "plc_outbound_full.json");
		if (!Files.exists(oriPath)) {
			logger.warning("The outbound policy file could not be found!");
			return;
		}
		File f = new File(oriPath.toString());
		String json = null;
		try {
			json = FileUtils.readFileToString(f, "UTF-8");
			logger.info("Read policy file success!");
		} catch (IOException e) {
			logger.warning(e.getMessage());
			logger.warning("Read policy file failed!");
			return;
		}
		if (json == null || json.equals("")) {
			logger.warning("JSON Format is not valid!");
			return;
		}
		JSONArray jsonArr = JSONArray.parseArray(json);
		logger.info("Policy Count: " + jsonArr.size());
		
		JSONArray result = new JSONArray();
		for (int i = 0; i < jsonArr.size(); i++) {
			JSONObject jsonOld = jsonArr.getJSONObject(i);
			String dstAddr = jsonOld.getString("dst_addr");
			String dstPort = jsonOld.getString("dst_port");
			if (!Util.isOpen(dstAddr, dstPort)) {
				// To prevent properties disorder
				JSONObject jsonNew = new JSONObject(new LinkedHashMap<String, Object>());
				jsonNew.put("dst_addr", dstAddr);
				jsonNew.put("dst_port", dstPort);
				result.add(jsonNew);
			}
		}
		logger.info("Unreachable policies count: " + result.size());
		String jsonResult = JSONArray.toJSONString(result, true);
		Path dmpPath = Paths.get(appPath, "plc_outbound_unreachable.json");
		if (!Files.exists(dmpPath)) {
			try {
				Files.createFile(dmpPath);
			} catch (IOException e) {
				logger.warning(e.getMessage());
				logger.warning("Cannot create new policy file!");
				return;
			}
		} else { // Reset this file
			File f2 = new File(dmpPath.toString());
			FileWriter fw = null;
			try {
				fw = new FileWriter(f2);
				fw.write("");
				fw.flush();
				fw.close();
			} catch (IOException e) {
				logger.severe("File emptying failed!");
			}
		}
		try {
			Files.write(dmpPath, jsonResult.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
			logger.info("Write policy file success!");
		} catch (IOException e) {
			logger.warning(e.getMessage());
			logger.warning("Cannot dump cleaned policy!");
			return;
		}
	}

}

/***********************************
 * Unified Task Assigner/Scheduler *
 * Author: Hugh                    *
 ***********************************/
package org.ayakaji;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class Assigner {
	private final static Logger logger = Logger.getLogger(Assigner.class.getName());

	public static void main(String[] args) {
		if (args.length == 0 || args[0].equals("-h") || args[0].equals("--h")) {
			logger.info("Pls provide at least 1 feature option: [ NetPolicyRebuilder, PortSniffer, cleanTransient ]");
		} else if (args[0].equals("PortSniffer")) {
			List<String> params = new ArrayList<String>();
			for (int i = 1; i < args.length; i++) {
				params.add(args[i]);
			}
			String[] subArgs = params.toArray(new String[0]);
			PortSniffer.main(subArgs);
		} else if (args[0].equals("cleanTransient")) {
			DBUtils.extern_clean_transient();
		}
	}
}

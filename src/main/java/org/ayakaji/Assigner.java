/***********************************
 * Unified Task Assigner/Scheduler *
 * Author: Hugh                    *
 ***********************************/
package org.ayakaji;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class Assigner {
	private final static Logger logger = Logger.getLogger(Assigner.class.getName());

	public static void main(String[] args)
			throws ClassNotFoundException, SQLException, PcapNativeException, NotOpenException, InterruptedException {
		if (args.length == 0 || args[0].equals("-h") || args[0].equals("--h")) {
			logger.info("Pls provide at least 1 feature option: [ NetPolicyRebuilder, PortSniffer, PolicyImport, CleanTransient ]");
			logger.info("Usage: java -jar <mvn-target>.jar NetPolicyRebuilder [<?minutes>]");
			logger.info("Usage: java -jar <mvn-target>.jar PortSniffer");
			logger.info("Usage: java -jar <mvn-target>.jar PolicyImport");
			logger.info("Usage: java -jar <mvn-target>.jar CleanTransient");
		} else if (args[0].equals("PortSniffer")) {
			List<String> params = new ArrayList<String>();
			for (int i = 1; i < args.length; i++) {
				params.add(args[i]);
			}
			String[] subArgs = params.toArray(new String[0]);
			PortSniffer.main(subArgs);
		} else if (args[0].equals("PolicyImport")) {
			DBUtils.main(new String[] {});
		} else if (args[0].equals("NetPolicyRebuilder")) {
			if (args.length > 1) NetPolicyRebuilder.main(new String[] { args[1] });
			else NetPolicyRebuilder.main(new String[] {});
		} else if (args[0].equals("CleanTransient")) {
			NetPolicyRebuilder.cleanTransient();
		}
	}
}

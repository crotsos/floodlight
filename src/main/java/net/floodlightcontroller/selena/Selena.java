package net.floodlightcontroller.selena;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.core.annotations.LogMessageCategory;
import net.floodlightcontroller.core.annotations.LogMessageDoc;
import net.floodlightcontroller.core.annotations.LogMessageDocs;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFPortStatisticsReply;
import org.openflow.protocol.statistics.OFPortStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("unused")
@LogMessageCategory("Flow Programming")
public class Selena extends ForwardingBase implements IFloodlightModule {
	
	class ServerProperties {
		public ServerProperties(byte[] mac, int ip) {
			this.mac = mac; 
			this.ip = ip;
		}
		byte[] mac;
		int    ip;
	}
	
	class PortStats {
		long last_bytes;
		long last_pkts;
		long bytes;
		long pkts;
	}
	
	private int currServers = 2;
	private ArrayList<ServerProperties> servers;
	private HashMap<Short,PortStats> ports;
	
    protected static Logger log = LoggerFactory.getLogger(Selena.class);

    @Override
    @LogMessageDoc(level="ERROR",
                   message="Unexpected decision made for this packet-in={}",
                   explanation="An unsupported PacketIn decision has been " +
                   		"passed to the flow programming component",
                   recommendation=LogMessageDoc.REPORT_CONTROLLER_BUG)
    public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision,
                                          FloodlightContext cntx) {

        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        
        // Construct the action bit of the flow_mod list
        ArrayList<OFAction> actions = new ArrayList<OFAction>();
        if (pi.getInPort() == 1) {
            // Choose uniformly at random a destination server
            int ix = match.getTransportSource() % currServers;
            ix = (ix < 0)?ix+currServers:ix;
            ServerProperties s = servers.get(ix);
            actions.add(new OFActionNetworkLayerDestination(s.ip));
            actions.add(new OFActionDataLayerSource( new byte[]{(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00, (byte)0x01} ));
            actions.add(new OFActionDataLayerDestination(s.mac));
            actions.add(new OFActionOutput((short)(ix+2)));
        } else {
            actions.add(new OFActionNetworkLayerSource(IPv4.toIPv4Address("192.168.1.1")));
            actions.add(new OFActionDataLayerSource( new byte[]{(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0x01,(byte)0x01, (byte)0x01}));
            actions.add(new OFActionDataLayerDestination(new byte[]{(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0x01,(byte)0x01, (byte)0x02}));
            actions.add(new OFActionOutput((short)1));
        } 
        
        // assemble flow_mod with action list 
        OFFlowMod fm =
                (OFFlowMod) floodlightProvider.getOFMessageFactory()
                                              .getMessage(OFType.FLOW_MOD);
        
        int len = OFFlowMod.MINIMUM_LENGTH 
      		  + (2*OFActionDataLayerSource.MINIMUM_LENGTH)
      		  + OFActionNetworkLayerSource.MINIMUM_LENGTH 
      		  + OFActionOutput.MINIMUM_LENGTH;
        long cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
        fm.setCookie(cookie)
          .setHardTimeout((short) 0)
          .setIdleTimeout((short) 10)
          .setBufferId(pi.getBufferId())
          .setMatch(match)
          .setActions(actions)
          .setLengthU(len);
    	log.info("write drop flow-mod len={} sw={} match={}",
    			new Object[] { len, sw, match});

        try {
            messageDamper.write(sw, fm, cntx);
        } catch (IOException e) {
            log.error("Failure writing drop flow mod", e);
        }
        
        return Command.STOP;
    }

    

    // IFloodlightModule methods

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // We don't export any services
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService>
            getServiceImpls() {
        // We don't have any services
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(IDeviceService.class);
        l.add(IRoutingService.class);
        l.add(ITopologyService.class);
        l.add(ICounterStoreService.class);
        l.add(IThreadPoolService.class);
        return l;
    }

    protected IThreadPoolService threadPool;
    
    @Override
    @LogMessageDocs({
        @LogMessageDoc(level="WARN",
                message="Error parsing flow idle timeout, " +
                        "using default of {number} seconds",
                explanation="The properties file contains an invalid " +
                        "flow idle timeout",
                recommendation="Correct the idle timeout in the " +
                        "properties file."),
        @LogMessageDoc(level="WARN",
                message="Error parsing flow hard timeout, " +
                        "using default of {number} seconds",
                explanation="The properties file contains an invalid " +
                            "flow hard timeout",
                recommendation="Correct the hard timeout in the " +
                                "properties file.")
    })
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        super.init();
        this.servers = new ArrayList<ServerProperties>();
        servers.add(new ServerProperties(new byte[]{(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00, (byte)0x02}, IPv4.toIPv4Address("192.168.1.2")) );
        servers.add(new ServerProperties(new byte[]{(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00, (byte)0x03}, IPv4.toIPv4Address("192.168.1.3")) );
        servers.add(new ServerProperties(new byte[]{(byte)0xfe,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00, (byte)0x04}, IPv4.toIPv4Address("192.168.1.4")) );
        
        this.ports = new HashMap<Short, PortStats>();
        
        this.floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceManager = context.getServiceImpl(IDeviceService.class);
        this.routingEngine = context.getServiceImpl(IRoutingService.class);
        this.topology = context.getServiceImpl(ITopologyService.class);
        this.counterStore = context.getServiceImpl(ICounterStoreService.class);
        this.threadPool = context.getServiceImpl(IThreadPoolService.class);

    }


    final static int STATS_REQ_DELAY = 10;
    protected SingletonTask discoveryTask;
    private int stats_count = 1000;
    
    @Override
    public void startUp(FloodlightModuleContext context) {
        super.startUp();
        
    	ScheduledExecutorService ses = threadPool.getScheduledExecutor();

		// List<IOFSwitch> sws = 
        // messageDamper.write(sw, fm, context);
   
		// To be started by the first switch connection
    	discoveryTask = new SingletonTask(ses, new Runnable() {
    		@Override
    		public void run() {
                OFStatisticsRequest req = new OFStatisticsRequest();
    			OFPortStatisticsRequest port = new OFPortStatisticsRequest();
    			req.setXid(stats_count++);
    			port.setPortNumber(OFPort.OFPP_NONE.getValue());
    			req.setStatistics(Collections.singletonList((OFStatistics)port));
    			req.setStatisticType(OFStatisticsType.PORT);
    			req.setLength((short)(OFStatisticsRequest.MINIMUM_LENGTH +port.getLength()));

    	        for (long sw : floodlightProvider.getAllSwitchDpids()) {
    	            IOFSwitch iofSwitch = floodlightProvider.getSwitch(sw);
    	            try {
    	                // System.out.println(sw.getStatistics(req));
    	                Future<List<OFStatistics>> future = iofSwitch.queryStatistics(req);
    	                List<OFStatistics> values = future.get(500, TimeUnit.MILLISECONDS);
    	                if (values != null) {
    	                    for (OFStatistics value : values) {
    	                    	OFPortStatisticsReply stats = (OFPortStatisticsReply)value;
    	                    	if (ports.containsKey(new Short(stats.getPortNumber()))) {
    	                    		PortStats st = ports.get(new Short(stats.getPortNumber()));
    	                    		st.bytes = stats.getReceiveBytes() - st.last_bytes;
    	                    		st.last_bytes = stats.getReceiveBytes();
    	                    		st.pkts = stats.getreceivePackets() - st.last_pkts;
    	                    		st.last_pkts = stats.getreceivePackets();
    	                    		
    	                    		float rate = (float)(8*st.bytes) / (float)(100*1e6);
    	                    		// plog.error("Port {} rate {}", new Object[]{stats.getPortNumber(), rate});
    	                    	} else {
    	                    		PortStats st = new PortStats();
    	                    		st.last_bytes = stats.getReceiveBytes();
    	                    		st.last_pkts = stats.getreceivePackets();
    	                    		ports.put(new Short(stats.getPortNumber()), st);
    	                    	}
    	                        
    	                    }
    	                }
    	            } catch (Exception e) {
    	                log.error("Failure retrieving statistics from switch " + sw, e);
    	            }
    	        }
    			
    			discoveryTask.reschedule(STATS_REQ_DELAY,
    					TimeUnit.SECONDS);
    		}

        });
        discoveryTask.reschedule(STATS_REQ_DELAY, TimeUnit.SECONDS);
    }
}

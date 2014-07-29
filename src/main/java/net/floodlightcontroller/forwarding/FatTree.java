/**
 * 
 */
package net.floodlightcontroller.forwarding;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;

/**
 * @author cr409
 *
 */
public class FatTree extends ForwardingBase implements IFloodlightModule, IOFSwitchListener {
    protected static Logger log = LoggerFactory.getLogger(FatTree.class);

	/**
	 * 
	 */
	public FatTree() {
		super();
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#getModuleServices()
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;		
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#getServiceImpls()
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#getModuleDependencies()
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(IDeviceService.class);
        l.add(IRoutingService.class);
        l.add(ITopologyService.class);
        l.add(ICounterStoreService.class);
        return l;
	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#init(net.floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.init();
        this.floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceManager = context.getServiceImpl(IDeviceService.class);
        this.routingEngine = context.getServiceImpl(IRoutingService.class);
        this.topology = context.getServiceImpl(ITopologyService.class);
        this.counterStore = context.getServiceImpl(ICounterStoreService.class);

	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.core.module.IFloodlightModule#startUp(net.floodlightcontroller.core.module.FloodlightModuleContext)
	 */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.startUp();

	}

	/* (non-Javadoc)
	 * @see net.floodlightcontroller.routing.ForwardingBase#processPacketInMessage(net.floodlightcontroller.core.IOFSwitch, org.openflow.protocol.OFPacketIn, net.floodlightcontroller.routing.IRoutingDecision, net.floodlightcontroller.core.FloodlightContext)
	 */
	@Override
	public Command processPacketInMessage(
			IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision,
			FloodlightContext cntx) {
		String[] dpid = sw.getStringId().split(":");
		
		int pod = Byte.parseByte(dpid[dpid.length - 2], 16);
		int swid =Byte.parseByte(dpid[dpid.length - 1], 16);
		
		OFMatch m = new OFMatch();
		m.loadFromPacket(pi.getPacketData(), pi.getInPort());
		ArrayList<OFAction> act = new ArrayList<OFAction>();
		
		String ip[] = IPv4.fromIPv4Address(m.getNetworkDestination()).split("\\.");
		byte dst_pod = Byte.parseByte(ip[1]), dst_swid = Byte.parseByte(ip[2]),
				dst_host = Byte.parseByte(ip[3]);
		
		if (m.getDataLayerType() == 0x8942 || m.getDataLayerType() == 0x4289)
			return Command.CONTINUE;
		
		/* middle layer switches - pod = 0...3*/
		if (pod >= 0 && pod < 4) {
			
			/* First layer switches */
			if (swid == 1 || swid == 2) {
				if (dst_pod == pod && swid == dst_swid) {
					act.add(new OFActionDataLayerSource( 
									new byte[] {(byte)0xfe, (byte)0xff, (byte)0xff, 
											dst_pod, dst_swid, (byte)1}));
					act.add(new OFActionDataLayerDestination( 
							new byte[] {(byte)0xfe, (byte)0xff, (byte)0xff, 
									dst_pod, dst_swid, dst_host}));
					act.add( new OFActionOutput((short)((int)dst_host - 1)));
				} else 
					act.add( new OFActionOutput((short)3));

			/* Second layer switches */
			} else {
				if (dst_pod == pod)
					act.add( new OFActionOutput((short)((int)dst_swid)));
				else 
					act.add( new OFActionOutput((short)3));
			}
		// top layer switches - pod = 4
		} else if (pod == 4) 
			act.add( new OFActionOutput((short)(dst_pod + 1)));

		short length = (short)OFFlowMod.MINIMUM_LENGTH;
		for (OFAction action : act) {
			length += action.getLength();
		}
		if (length > (short)OFMatch.MINIMUM_LENGTH) {
			OFMessage fm = (new OFFlowMod())
			.setIdleTimeout((short) 60)
			.setHardTimeout((short) 0)
			.setActions(act)
			.setBufferId(pi.getBufferId())
			.setCommand(OFFlowMod.OFPFC_ADD)
			.setMatch(m)
			.setLengthU(length);
			
			try {
				this.messageDamper.write(sw, fm, cntx);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		return Command.STOP;
	}

	@Override
	public void switchAdded(long switchId) {
		// TODO Auto-generated method stub
		OFMatch m = new OFMatch();
		IOFSwitch sw = floodlightProvider.getSwitch(switchId);
		
		int length = (short)OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH;

		ArrayList<OFAction> act = new ArrayList<OFAction>();
		act.add( new OFActionOutput(org.openflow.protocol.OFPort.OFPP_LOCAL.getValue()));
		
		m.setWildcards(Wildcards.ofMatches(Wildcards.Flag.IN_PORT));	
		m.setInputPort((short)5);
		
		OFMessage fm = (new OFFlowMod())
				.setIdleTimeout((short) 0)
				.setHardTimeout((short) 0)
				.setActions(act)
				.setBufferId(-1)
				.setCommand(OFFlowMod.OFPFC_ADD)
				.setMatch(m)
				.setLengthU(length);
        try {
            sw.write(fm, null);
            sw.flush();
        } catch (IOException e) {
            log.error("Tried to write OFFlowMod to {} but failed: {}",
                    HexString.toHexString(sw.getId()), e.getMessage());
        }
        
		act = new ArrayList<OFAction>();
		act.add( new OFActionOutput((short)5));
		
		m.setWildcards(Wildcards.ofMatches(Wildcards.Flag.IN_PORT));	
		m.setInputPort(org.openflow.protocol.OFPort.OFPP_LOCAL.getValue());
		
		fm = (new OFFlowMod())
				.setIdleTimeout((short) 0)
				.setHardTimeout((short) 0)
				.setActions(act)
				.setBufferId(-1)
				.setCommand(OFFlowMod.OFPFC_ADD)
				.setMatch(m)
				.setLengthU(length);    
		try {
			sw.write(fm, null);
			sw.flush();
		} catch (IOException e) {
			log.error("Tried to write OFFlowMod to {} but failed: {}",
					HexString.toHexString(sw.getId()), e.getMessage());
		}

	}

	@Override
	public void switchRemoved(long switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchActivated(long switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(long switchId) {
		// TODO Auto-generated method stub
		
	}
}

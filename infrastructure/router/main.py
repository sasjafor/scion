# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`router` --- SCION border router
===========================================
"""
# Stdlib
import logging
import threading
import time
import zlib
from collections import defaultdict

# External packages
from Crypto.Protocol.KDF import PBKDF2

# SCION
from external.expiring_dict import ExpiringDict
from infrastructure.router.if_state import InterfaceState
from infrastructure.router.errors import (
    SCIONIFVerificationError,
    SCIONInterfaceDownException,
    SCIONOFExpiredError,
    SCIONOFVerificationError,
    SCIONPacketHeaderCorruptedError,
    SCIONSegmentSwitchError,
)
from infrastructure.scion_elem import SCIONElement
from lib.defines import (
    BEACON_SERVICE,
    EXP_TIME_UNIT,
    IFID_PKT_TOUT,
    MAX_HOPBYHOP_EXT,
    PATH_SERVICE,
    ROUTER_SERVICE,
    SCION_UDP_EH_DATA_PORT,
)
from lib.errors import (
    SCIONBaseError,
    SCIONServiceLookupError, SCIONBaseException)
from lib.log import log_exception
from lib.msg_meta import RawMetadata
from lib.packet.svc import SVC_TO_SERVICE
from lib.sibra.ext.ext import SibraExtBase
from lib.packet.ext.one_hop_path import OneHopPathExt
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.ifid import IFIDPayload
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.path import SCIONPath, valid_hof
from lib.packet.path_mgmt.ifstate import IFStateInfo, IFStateRequest
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scion_addr import SCIONAddr, ISD_AS
from lib.packet.scmp.errors import (
    SCMPBadExtOrder,
    SCMPBadHopByHop,
    SCMPBadIF,
    SCMPBadMAC,
    SCMPDeliveryFwdOnly,
    SCMPDeliveryNonLocal,
    SCMPError,
    SCMPExpiredHOF,
    SCMPNonRoutingHOF,
    SCMPPathRequired,
    SCMPTooManyHopByHop,
    SCMPUnknownHost,
)
from lib.packet.scmp.ext import SCMPExt
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
# from lib.packet.svc import SVCType, SVC_TO_SERVICE
from lib.sibra.state.state import SibraState
from lib.socket import UDPSocket, udp_send
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    ExtHopByHopType,
    ExtensionClass,
    LinkType,
    PathMgmtType as PMT,
    PayloadClass,
    RouterFlag,
)
from lib.util import SCIONTime, hex_str, sleep_interval


from nagini_contracts.contracts import *
from nagini_contracts.io_builtins import Place, token, IOOperation, IOExists1, Terminates, MustTerminate


# for type annotations
from typing import List, Tuple, Union, Callable, cast, Optional, Dict, Any, Iterable
from lib.packet.scion import SCIONL4Packet, packed
from lib.packet.host_addr import HostAddrBase
from lib.util import Raw
from lib.topology import InterfaceElement, RouterElement


class Router(SCIONElement):
    """
    The SCION Router.

    :ivar interface: the router's inter-AS interface, if any.
    :type interface: :class:`lib.topology.InterfaceElement`
    """
    # SERVICE_TYPE = ROUTER_SERVICE
    FWD_REVOCATION_TIMEOUT = 5
    IFSTATE_REQ_INTERVAL = 30

    def __init__(self, server_id: str, conf_dir: str) -> None:
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir, )
        self._udp_sock = UDPSocket(addr_type=self.addr.host.TYPE)
        self.interface = None  # type: InterfaceElement
        for border_router in self.topology.get_all_border_routers():
            if border_router.name == self.id:
                self.interface = border_router.interface
                break
        assert self.interface is not None
        # logging.info("Interface: %s", self.interface.__dict__)
        self.is_core_router = self.topology.is_core_as
        self.of_gen_key = PBKDF2(self.config.master_as_key, b"Derive OF Key")
        self.sibra_key = PBKDF2(self.config.master_as_key, b"Derive SIBRA Key")
        self.if_states = defaultdict(InterfaceState)  # type: defaultdict[int, InterfaceState]
        self.revocations = ExpiringDict(1000, self.FWD_REVOCATION_TIMEOUT)  # type: ExpiringDict[RevocationInfo, bool]
        self.pre_ext_handlers = {
            SibraExtBase.EXT_TYPE: True,
            TracerouteExt.EXT_TYPE: True,
            OneHopPathExt.EXT_TYPE: True,
            ExtHopByHopType.SCMP: True,
        }
        self.post_ext_handlers = {
            SibraExtBase.EXT_TYPE: False, TracerouteExt.EXT_TYPE: False,
            ExtHopByHopType.SCMP: False, OneHopPathExt.EXT_TYPE: False,
        }
        self.sibra_state = SibraState(
            self.interface.bandwidth,
            "%s#%s -> %s" % (self.addr.isd_as, self.interface.if_id,
                             self.interface.isd_as))
        # self.CTRL_PLD_CLASS_MAP = {
        #     PayloadClass.IFID: {None: self.process_ifid_request},
        #     PayloadClass.PATH: defaultdict(
        #         lambda: self.process_path_mgmt_packet),
        # }
        # self.SCMP_PLD_CLASS_MAP = {
        #     SCMPClass.PATH: {SCMPPathClass.REVOKED_IF: self.process_revocation},
        # }
        self._remote_sock = UDPSocket(
            bind=(str(self.interface.addr), self.interface.udp_port),
            addr_type=self.interface.addr.TYPE,
        )
        # self._socks.add(self._remote_sock, self.handle_recv)
        logging.info("IP %s:%d", self.interface.addr, self.interface.udp_port)

    @Predicate
    def State(self) -> bool:
        return (Acc(self.interface) and self.interface.State() and
                Acc(self._remote_sock) and Acc(self._udp_sock) and
                Acc(self.of_gen_key) and
                Acc(self.if_states) and dict_pred(self.if_states) and
                Forall(self.if_states, lambda x: (self.if_states[x].State())) and
                Acc(self.pre_ext_handlers) and
                Acc(self.post_ext_handlers))

    # @ContractOnly
    # @Pure
    # def get_if_states_seq(self) -> Sequence[InterfaceState]:
    #     Ensures(Forall(cast(Sequence[InterfaceState], Result()), lambda x: (x in self.if_states.values())))
    #     # helper method to return the values of self.if_states
    #     pass

    def _service_type(self) -> Optional[str]:
        return ROUTER_SERVICE

    # def _setup_sockets(self, init=True):
    #     """
    #     Setup incoming socket
    #     """
    #     self._udp_sock = UDPSocket(
    #         bind=(str(self.addr.host), self._port, self.id),
    #         addr_type=self.addr.host.TYPE,
    #     )
    #     self._port = self._udp_sock.port
    #     self._socks.add(self._udp_sock, self.handle_recv)
    #
    # def run(self):
    #     """
    #     Run the router threads.
    #     """
    #     threading.Thread(
    #         target=thread_safety_net, args=(self.sync_interface,),
    #         name="BR.sync_interface", daemon=True).start()
    #     threading.Thread(
    #         target=thread_safety_net, args=(self.request_ifstates,),
    #         name="BR.request_ifstates", daemon=True).start()
    #     threading.Thread(
    #         target=thread_safety_net, args=(self.sibra_worker,),
    #         name="BR.sibra_worker", daemon=True).start()
    #     SCIONElement.run(self)

    def send(self, t: Place, packet: SCIONL4Packet, dst: HostAddrBase, dst_port: int) -> Place:
        # IOExists1(Place)(lambda t2: (
        #     Requires(Acc(self.State(), 1/9) and Acc(packet.State(), 1/8) and Unfolding(Acc(packet.State(), 1/100), len(packet.ext_hdrs) == 0)),
        #     Requires(token(t, 2) and udp_send(t, packed(packet), str(dst), dst_port, t2)),
        #     Ensures(Acc(self.State(), 1/9) and Acc(packet.State(), 1/8) and Result() is t2 and token(t2))
        # ))
        Requires(Acc(self.State(), 1/10))
        Requires(Acc(packet.State(), 1/9))
        Requires(packet.get_ext_hdrs_len() == 0)
        Requires(MustTerminate(3))
        Ensures(Acc(self.State(), 1/10))
        Ensures(Acc(packet.State(), 1/9))
        # Exsures(SCIONBaseError, Acc(self.State(), 1/10))
        # Exsures(SCIONBaseError, Acc(packet.State(), 1/9))
        # Exsures(SCIONBaseError, Acc(RaisedException().args_))
        """
        Send a packet to dst (class of that object must implement
        __str__ which returns IP addr string) using port and local or remote
        socket.

        :param packet: The packet to send.
        :type packet: :class:`lib.spkt.SCIONspkt`
        :param dst: The address of the next hop.
        :type dst: :class:`HostAddrBase`
        :param int dst_port: The port number of the next hop.
        """
        from_local_as = dst == self.get_interface_to_addr()
        self.handle_extensions(packet, False, from_local_as)
        Unfold(Acc(self.State(), 1/10))
        if from_local_as:
            result = self._remote_sock.send(t, packet.pack(), (str(dst), dst_port))
        else:
            result = self._udp_sock.send(t, packet.pack(), (str(dst), dst_port))
        Fold(Acc(self.State(), 1/10))
        return result[1]

    def handle_extensions(self, spkt: SCIONL4Packet, pre_routing_phase: bool, from_local_as: bool) -> List[Tuple[int, ...]]:
        """
        Handle SCION Packet extensions. Handlers can be defined for pre- and
        post-routing.
        """
        Requires(Acc(spkt.State(), 1/9))
        Requires(Acc(self.State(), 1/10))
        Requires(spkt.get_ext_hdrs_len() == 0)
        Requires(MustTerminate(2))
        Ensures(Acc(list_pred(Result())))
        Ensures(Acc(spkt.State(), 1/9))
        Ensures(Acc(self.State(), 1/10))
        Ensures(len(Result()) == 0)
        if pre_routing_phase:
            prefix = "pre"
            handlers = self.get_pre_ext_handlers() # type: Dict[int, bool]
        else:
            prefix = "post"
            handlers = self.get_post_ext_handlers()
        flags = []  # type: List[Tuple[int, ...]]
        # Hop-by-hop extensions must be first (just after path), and process
        # only MAX_HOPBYHOP_EXT number of them. If an SCMP ext header is
        # present, it must be the first hopbyhop extension (and isn't included
        # in the MAX_HOPBYHOP_EXT check).
        count = 0
        ext_hdrs = spkt.get_ext_hdrs()
        Unfold(Acc(spkt.State(), 1/9))
        ext_hdrs_enum = enumerate(ext_hdrs)
        Fold(Acc(spkt.State(), 1/9))
        for i, ext_hdr in ext_hdrs_enum:
            Invariant(Acc(spkt.State(), 1/9))
            Invariant(spkt.get_ext_hdrs_len() == 0)
            Invariant(MustTerminate(1))
            # assert False
            if ext_hdr.EXT_CLASS != ExtensionClass.HOP_BY_HOP:
                break
            if ext_hdr.EXT_TYPE == ExtHopByHopType.SCMP:
                if i != 0:
                    logging.error("SCMP ext header not first.")
                    raise SCMPBadExtOrder(i)
            else:
                count += 1
            if count > MAX_HOPBYHOP_EXT:
                logging.error("Too many hop-by-hop extensions.")
                raise SCMPTooManyHopByHop(i)
            handler = handlers.get(ext_hdr.EXT_TYPE) # type: Optional[bool]
            if handler is None:
                logging.debug("No %s-handler for extension type %s",
                              prefix, ext_hdr.EXT_TYPE)
                raise SCMPBadHopByHop
            if handler:
                # new code because of types
                if isinstance(ext_hdr, SCMPExt):
                    flags.extend(cast(List[Tuple[int]], self.handle_scmp(cast(SCMPExt, ext_hdr), spkt, from_local_as)))
                elif isinstance(ext_hdr, TracerouteExt):
                    flags.extend(cast(List[Tuple[int, ...]], self.handle_traceroute(cast(TracerouteExt, ext_hdr), spkt, from_local_as)))
                elif isinstance(ext_hdr, SibraExtBase):
                    flags.extend(cast(List[Tuple[int, ...]], self.handle_sibra(cast(SibraExtBase, ext_hdr), spkt, from_local_as)))
                elif isinstance(ext_hdr, ExtensionHeader):
                    flags.extend(cast(List[Tuple[int]], self.handle_one_hop_path(cast(ExtensionHeader, ext_hdr), spkt, from_local_as)))
        return flags

    @ContractOnly
    def handle_traceroute(self, hdr: TracerouteExt, spkt: SCIONL4Packet, _: bool) -> List[Tuple[int, str]]:
        Requires(True)
        # hdr.append_hop(self.addr.isd_as, self.interface.if_id)
        # return []

    @ContractOnly
    def handle_one_hop_path(self, hdr: ExtensionHeader, spkt: SCIONL4Packet, from_local_as: bool) -> List[Tuple[int]]:
        Requires(True)
        # if len(spkt.path) != InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN:
        #     logging.error("OneHopPathExt: incorrect path length.")
        #     return [(RouterFlag.ERROR,)]
        # if not from_local_as:  # Remote packet, create the 2nd Hop Field
        #     info = spkt.path.get_iof() # type: Optional[InfoOpaqueField]
        #     hf1 = spkt.path.get_hof_ver(ingress=True)
        #     exp_time = OneHopPathExt.HOF_EXP_TIME
        #     hf2 = HopOpaqueField.from_values(exp_time, self.interface.if_id, 0)
        #     hf2.set_mac(self.of_gen_key, info.timestamp, hf1)
        #     # FIXME(PSz): quite brutal for now:
        #     spkt.path = SCIONPath.from_values(info, [hf1, hf2])
        #     spkt.path.inc_hof_idx()
        # return []

    @ContractOnly
    def handle_sibra(self, hdr: SibraExtBase, spkt: SCIONL4Packet, from_local_as: bool) -> List[Tuple[int, str]]:
        Requires(True)
        # ret = hdr.process(self.sibra_state, spkt, from_local_as,
        #                   self.sibra_key)
        # logging.debug("Sibra state:\n%s", self.sibra_state)
        # return ret

    @ContractOnly
    def handle_scmp(self, hdr: SCMPExt, spkt: SCIONL4Packet, _: bool) -> List[Tuple[int]]:
        Requires(True)
        # if hdr.hopbyhop:
        #     return [(RouterFlag.PROCESS_LOCAL,)]
        # return []

    # def sync_interface(self):
    #     """
    #     Synchronize and initialize the router's interface with that of a
    #     neighboring router.
    #     """
    #     ifid_pld = IFIDPayload.from_values(self.interface.if_id)
    #     pkt = self._build_packet(self.interface.to_addr,
    #                              dst_ia=self.interface.isd_as)
    #     while self.run_flag.is_set():
    #         pkt.set_payload(ifid_pld.copy())
    #         self.send(pkt, self.interface.to_addr, self.interface.to_udp_port)
    #         time.sleep(IFID_PKT_TOUT)
    #
    # def request_ifstates(self):
    #     """
    #     Periodically request interface states from the BS.
    #     """
    #     pld = IFStateRequest.from_values()
    #     while self.run_flag.is_set():
    #         start_time = SCIONTime.get_time()
    #         logging.info("Sending IFStateRequest for all interfaces.")
    #         for bs in self.topology.beacon_servers:
    #             req = self._build_packet(bs.addr, dst_port=bs.port,
    #                                      payload=pld.copy())
    #             self.send(req, bs.addr, SCION_UDP_EH_DATA_PORT)
    #         sleep_interval(start_time, self.IFSTATE_REQ_INTERVAL,
    #                        "request_ifstates")
    #
    # def sibra_worker(self):
    #     while self.run_flag.is_set():
    #         start_time = SCIONTime.get_time()
    #         self.sibra_state.update_tick()
    #         sleep_interval(start_time, 1.0, "sibra_worker")
    #
    # def process_ifid_request(self, pkt, from_local):
    #     """
    #     After receiving IFID_PKT from neighboring router it is completed (by
    #     iface information) and passed to local BSes.
    #
    #     :param ifid_packet: the IFID request packet to send.
    #     :type ifid_packet: :class:`lib.packet.scion.IFIDPacket`
    #     """
    #     if from_local:
    #         logging.error("Received IFID packet from local AS, dropping")
    #         return
    #     ifid_pld = pkt.get_payload().copy()
    #     # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
    #     # BS must determine interface.
    #     ifid_pld.p.relayIF = self.interface.if_id
    #     try:
    #         bs_addrs = self.dns_query_topo(BEACON_SERVICE)
    #     except SCIONServiceLookupError as e:
    #         logging.error("Unable to deliver ifid packet: %s", e)
    #         raise SCMPUnknownHost
    #     # Only deliver once per address, as the multicast SVC address will cover
    #     # all instances on that address.
    #     pkt = self._build_packet(SVCType.BS_M)
    #     for addr in set([a for a, _ in bs_addrs]):
    #         pkt.set_payload(ifid_pld.copy())
    #         self.send(pkt, addr, SCION_UDP_EH_DATA_PORT)

    @ContractOnly
    def get_srv_addr(self, service: str, pkt: SCIONL4Packet) -> HostAddrBase:
        Requires(MustTerminate(3))
        """
        For a given service return a server address. Guarantee that all packets
        from the same source to a given service are sent to the same server.

        :param str service: Service to query for.
        :type pkt: :class:`lib.packet.scion.SCIONBasePacket`

        """
        addrs = self.dns_query_topo(service)
        addrs.sort()  # To not rely on order of DNS replies.
        return addrs[zlib.crc32(pkt.addrs.pack()) % len(addrs)][0]

    # def process_path_mgmt_packet(self, mgmt_pkt, from_local_as):
    #     """
    #     Process path management packets.
    #
    #     :param mgmt_pkt: The path mgmt packet.
    #     :type mgmt_pkt: :class:`lib.packet.path_mgmt.PathMgmtPacket`
    #     :param bool from_local_as:
    #         whether or not the packet is from the local AS.
    #     """
    #     payload = mgmt_pkt.get_payload()
    #     if payload.PAYLOAD_TYPE == PMT.IFSTATE_INFOS:
    #         # handle state update
    #         logging.debug("Received IFState update:\n%s",
    #                       str(mgmt_pkt.get_payload()))
    #         for p in payload.p.infos:
    #             self.if_states[p.ifID].update(IFStateInfo(p))
    #         return
    #     self.handle_data(mgmt_pkt, from_local_as)
    #
    # def process_revocation(self, spkt, from_local_as):
    #     pld = spkt.get_payload()
    #     logging.info("Processing revocation: %s", pld.info)
    #     # First, forward the packet as appropriate.
    #     self.handle_data(spkt, from_local_as)
    #     if from_local_as:
    #         return
    #     # Forward to local path and beacon services if we haven't recently.
    #     rev_info = RevocationInfo.from_raw(pld.info.rev_info)
    #     if rev_info in self.revocations:
    #         return
    #     snames = []
    #     # Fork revocation to local BS and PS if router is downstream of the
    #     # failed interface.
    #     if (spkt.addrs.src.isd_as[0] == self.addr.isd_as[0] and
    #             self._is_downstream_router()):
    #         snames.append(BEACON_SERVICE)
    #         if self.topology.path_servers:
    #             snames.append(PATH_SERVICE)
    #     # Fork revocation to local PS if router is in the AS of the source.
    #     elif (spkt.addrs.dst.isd_as == self.addr.isd_as and
    #             self.topology.path_servers):
    #         snames.append(PATH_SERVICE)
    #
    #     self.revocations[rev_info] = True
    #     for sname in snames:
    #         try:
    #             addr, port = self.dns_query_topo(sname)[0]
    #         except SCIONServiceLookupError:
    #             logging.error("Unable to find %s to forward revocation to.",
    #                           sname)
    #             continue
    #         pkt = self._build_packet(addr, dst_port=port,
    #                                  payload=rev_info.copy())
    #         self.send(pkt, addr, SCION_UDP_EH_DATA_PORT)
    #
    # def _is_downstream_router(self):
    #     """
    #     Returns True if this router is connected to an upstream router (via an
    #     upstream link), False otherwise.
    #     """
    #     return self.interface.link_type == LinkType.PARENT
    #

    @ContractOnly
    def send_revocation(self, t: Place, spkt: SCIONL4Packet, if_id: int, ingress: bool, path_incd: bool) -> None:
        Requires(Acc(self.State(), 1/10))
        Requires(MustTerminate(5))
        # Requires(Unfolding(Acc(self.State(), 1/10), self.if_states.__contains__(if_id)))
        Ensures(Acc(self.State(), 1/10))
        """
        Sends an interface revocation for 'if_id' along the path in 'spkt'.
        """
        logging.info("Interface %d is down. Issuing revocation.", if_id)
        # Check that the interface is really down.
        if_state = Unfolding(Acc(self.State(), 1/10), self.if_states[if_id])
        if Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self.if_states[if_id].State(), 1/10), self.if_states[if_id].is_active)):
            # logging.error("Interface %d appears to be up. Not sending " +
            #               "revocation." % if_id)
            return

        assert if_state.rev_info, "Revocation token missing."

        rev_pkt = cast(SCIONL4Packet, spkt.reversed_copy()) # type: SCIONL4Packet
        rev_pkt.convert_to_scmp_error(
            self.addr, SCMPClass.PATH, SCMPPathClass.REVOKED_IF, spkt, if_id,
            ingress, if_state.rev_info.copy(), hopbyhop=True)
        if path_incd:
            rev_pkt.path.inc_hof_idx()
        rev_pkt.update()
        logging.debug("Revocation Packet:\n%s" % rev_pkt.short_desc())
        # FIXME(kormat): In some circumstances, this doesn't actually work, as
        # handle_data will try to send the packet to this interface first, and
        # then drop the packet as the interface is down.
        self.handle_data(t, rev_pkt, ingress, drop_on_error=True)

    def deliver(self, t: Place, spkt: SCIONL4Packet, force: bool=True) -> None:
        Requires(Acc(spkt.State(), 1/9))
        Requires(Acc(self.State(), 1/9))
        Requires(dict_pred(SVC_TO_SERVICE))
        Requires(spkt.get_addrs() is not None)
        Requires(spkt.get_path() is not None)
        Requires(spkt.get_addrs_dst() is not None)
        Requires(spkt.get_addrs_dst_host() is not None)
        Requires(spkt.get_path_hof_idx() is not None)
        Requires(spkt.get_ext_hdrs_len() == 0)
        Requires(MustTerminate(4))
        Ensures(Acc(spkt.State(), 1/9))
        Ensures(Acc(self.State(), 1/9))
        Ensures(dict_pred(SVC_TO_SERVICE))
        Exsures(SCMPDeliveryNonLocal, Acc(spkt.State(), 1/9))
        Exsures(SCMPDeliveryNonLocal, Acc(self.State(), 1/9))
        Exsures(SCMPDeliveryNonLocal, Acc(RaisedException().args_))
        Exsures(SCMPDeliveryNonLocal, dict_pred(SVC_TO_SERVICE))
        Exsures(SCMPDeliveryFwdOnly, Acc(spkt.State(), 1 / 9))
        Exsures(SCMPDeliveryFwdOnly, Acc(self.State(), 1 / 9))
        Exsures(SCMPDeliveryFwdOnly, Acc(RaisedException().args_))
        Exsures(SCMPDeliveryFwdOnly, dict_pred(SVC_TO_SERVICE))
        Exsures(SCMPNonRoutingHOF, Acc(spkt.State(), 1 / 9))
        Exsures(SCMPNonRoutingHOF, Acc(self.State(), 1 / 9))
        Exsures(SCMPNonRoutingHOF, Acc(RaisedException().args_))
        Exsures(SCMPNonRoutingHOF, dict_pred(SVC_TO_SERVICE))
        Exsures(SCMPUnknownHost, Acc(spkt.State(), 1 / 9))
        Exsures(SCMPUnknownHost, Acc(self.State(), 1 / 9))
        Exsures(SCMPUnknownHost, Acc(RaisedException().args_))
        Exsures(SCMPUnknownHost, dict_pred(SVC_TO_SERVICE))
        """
        Forwards the packet to the end destination within the current AS.
        #     :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param bool force:
            If set, allow packets to be delivered locally that would otherwise
            be disallowed.
        """
        # if not force and spkt.get_addrs_dst_isd_as() != self.get_addr_isd_as():
        spkt_isd_as = spkt.get_addrs_dst_isd_as()
        self_isd_as = self.get_addr_isd_as()
        if not force and not ((spkt_isd_as is None and self_isd_as is None) or (spkt_isd_as is not None and self.eq_isd_as(spkt))):
            logging.error("Tried to deliver a non-local packet:\n%s", spkt)
            raise SCMPDeliveryNonLocal
        if spkt.get_path_len():
            hof = spkt.get_path_hof()
            if not force and spkt.get_path_hof_forward_only(hof):
                raise SCMPDeliveryFwdOnly
            if spkt.get_path_hof_verify_only(hof):
                raise SCMPNonRoutingHOF
        # Forward packet to destination.
        addr = spkt.get_addrs_dst_host()
        if addr.TYPE is not None and addr.TYPE == AddrType.SVC:
            # Send request to any server.
            if SVC_TO_SERVICE.__contains__(spkt.get_addrs_dst_host_addr()):
                service = SVC_TO_SERVICE[spkt.get_addrs_dst_host_addr()]
                addr = self.get_srv_addr(service, spkt)
            # except SCIONServiceLookupError as e:
            else:
                # logging.error("Unable to deliver path mgmt packet: %s", e)
                raise SCMPUnknownHost
        self.send(t, spkt, addr, SCION_UDP_EH_DATA_PORT)

    def verify_hof(self, path: SCIONPath, ingress: bool = True) -> None:
        Requires(Acc(path.State(), 1/9))
        Requires(Acc(self.State(), 1/9))
        Requires(path.get_iof_idx() is not None)
        Requires(path.get_hof_idx() is not None)
        Requires(Implies(not ingress,
                         path.get_hof_idx() + 1 < path.get_ofs_len() and
                         isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 1), HopOpaqueField) and
                         path.ofs_get_by_idx(path.get_hof_idx() + 1) is not path.ofs_get_by_idx(path.get_hof_idx())
                         )
                 )
        Requires(MustTerminate(5))
        Ensures(Acc(path.State(), 1/9))
        Ensures(Acc(self.State(), 1/9))
        Ensures(path.get_iof_idx() is not None)
        Ensures(path.get_hof_idx() is not None)
        Ensures(valid_hof(path))
        Exsures(SCIONBaseError, Acc(path.State(), 1/9))
        Exsures(SCIONBaseError, Acc(self.State(), 1/9))
        Exsures(SCIONBaseError, Acc(RaisedException().args_))
        Exsures(SCIONIFVerificationError, len(RaisedException().args_) == 2)
        Exsures(SCIONOFVerificationError, len(RaisedException().args_) == 2)
        #Exsures(SCIONBaseError, not valid_hof(path))
        """Verify freshness and authentication of an opaque field."""
        iof = path.get_iof()
        ts = path.get_iof_timestamp(iof)
        hof = path.get_hof()
        prev_hof = path.get_hof_ver(ingress=ingress)
        # Check that the interface in the current hop field matches the
        # interface in the router.
        if path.get_curr_if(ingress=ingress) != self.get_interface_if_id():
            raise SCIONIFVerificationError(hof, iof)
        if int(SCIONTime.get_time()) <= ts + path.get_hof_exp_time(hof) * EXP_TIME_UNIT:
            if not Unfolding(Acc(path.State(), 1/10), Unfolding(Acc(path._ofs.State(), 1/10), hof.verify_mac(self.get_of_gen_key(), ts, prev_hof))):
                raise SCIONOFVerificationError(hof, prev_hof)
        else:
            raise SCIONOFExpiredError(hof)

    def _egress_forward(self, t: Place, spkt: SCIONL4Packet) -> Place:
        Requires(Acc(self.State(), 1/10))
        Requires(Acc(spkt.State(), 1/9))
        Requires(self.get_interface_to_addr() is not None)
        # Requires(Unfolding(Acc(spkt.State(), 1/10), len(spkt.ext_hdrs) == 0))
        Requires(spkt.get_ext_hdrs_len() == 0)
        Requires(MustTerminate(4))
        Ensures(Acc(self.State(), 1/10))
        Ensures(Acc(spkt.State(), 1/9))
        # Exsures(SCIONBaseError, Acc(self.State(), 1/10))
        # Exsures(SCIONBaseError, Acc(spkt.State(), 1/9))
        # Exsures(SCIONBaseError, Acc(RaisedException().args_))
        addr = self.get_interface_to_addr()
        port = self.get_interface_to_udp_port()
        logging.debug("Forwarding to remote interface: %s:%s",
                      addr, port)
        return self.send(t, spkt, addr, port)

    def handle_data(self, t: Place, spkt: SCIONL4Packet, from_local_as: bool, drop_on_error: bool=False) -> Place:
        Requires(Acc(spkt.State()))
        Requires(Acc(self.State(), 1/2))
        Requires(self.get_topology_mtu() is not None)
        Requires(self.get_interface_to_addr() is not None)
        Requires(spkt.get_path() is not None)
        Requires(spkt.get_addrs() is not None)
        Requires(spkt.get_addrs_dst() is not None)
        Requires(spkt.get_path_iof_idx() is not None)
        Requires(spkt.get_path_hof_idx() is not None)
        Requires(spkt.get_addrs_dst_host() is not None)
        Requires(spkt.get_ext_hdrs_len() == 0)
        Requires(dict_pred(SVC_TO_SERVICE))
        Requires(Implies(from_local_as,
                         Let(spkt.get_path(), bool, lambda path:
                         Unfolding(Acc(spkt.State(), 1 / 10),
                                   path.get_hof_idx() + 1 < path.get_ofs_len() and
                                   isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 1), HopOpaqueField) and
                                   path.ofs_get_by_idx(path.get_hof_idx() + 1) is not path.ofs_get_by_idx(
                                       path.get_hof_idx())
                                   )))
                 )
        Requires(Unfolding(Acc(spkt.State(), 1 / 10), Let(spkt.path, bool, lambda path:
                    path.get_hof_idx() < path.get_ofs_len() - 1 and
                    Let(cast(HopOpaqueField, Unfolding(Acc(path.State(), 1 / 10), path._ofs.get_by_idx(path._hof_idx + 1))), bool, lambda hof:
                        not path.get_hof_verify_only(hof)) and
                    path.get_hof_idx() - path.get_iof_idx() < path.get_iof_hops(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx()))) and
                    Let(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx())), bool, lambda iof:
                        Implies((Let(cast(HopOpaqueField, path.ofs_get_by_idx(path.get_hof_idx() + 1)), bool, lambda hof:
                            not path.get_hof_xover(hof) or
                            path.get_iof_shortcut(iof)
                        ) and
                        (path.get_hof_idx() != path.get_iof_idx() + path.get_iof_hops(iof))),
                        path.get_hof_idx() + 2 < path.get_ofs_len() and
                        isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField) and
                        path.ofs_get_by_idx(path.get_hof_idx() + 2) is not path.ofs_get_by_idx(path.get_hof_idx() + 1)
                        )
                    ) and
                    Implies(path.get_hof_idx() < path.get_ofs_len() - 2,
                    isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField))))
                )
        Requires(MustTerminate(self.get_topology_border_routers_len() + 7))
        Ensures(Acc(spkt.State()))
        Ensures(Acc(self.State(), 1/2))
        Ensures(dict_pred(SVC_TO_SERVICE))
        Exsures(SCIONBaseException, Acc(spkt.State()))
        Exsures(SCIONBaseException, Acc(self.State(), 1/2))
        Exsures(SCIONBaseException, dict_pred(SVC_TO_SERVICE))
        """
        Main entry point for data packet handling.

        :param spkt: The SCION Packet to process.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_as:
            Whether or not the packet is from the local AS.
        """
        if spkt.get_path_len() == 0:
            raise SCMPPathRequired()
        ingress = not from_local_as
        try:
            return self._process_data(t, spkt, ingress, drop_on_error)
        except SCIONIFVerificationError as e:
            logging.error("Dropping packet due to not matching interfaces.\n"
                          "Current IOF: %s\nCurrent HOF: %s\n"
                          "Router Interface: %d" %
                          (e.args_[1], e.args_[0], self.interface.if_id))
        except SCIONOFVerificationError as e:
            logging.error("Dropping packet due to incorrect MAC.\n"
                          "Header:\n%s\nInvalid OF: %s\nPrev OF: %s",
                          spkt, e.args_[0], e.args_[1])
            raise SCMPBadMAC from None
        except SCIONOFExpiredError as e:
            logging.error("Dropping packet due to expired OF.\n"
                          "Header:\n%s\nExpired OF: %s",
                          spkt, e)
            raise SCMPExpiredHOF from None
        except SCIONPacketHeaderCorruptedError:
            logging.error("Dropping packet due to invalid header state.\n"
                          "Header:\n%s", spkt)
        except SCIONSegmentSwitchError as e:
            logging.error("Dropping packet due to disallowed segment switch: "
                          "%s" % e.args_[0])
        except SCIONInterfaceDownException:
            logging.info("Dropping packet due to interface being down.")
            pass
        return t

    def _process_data(self, t: Place, spkt: SCIONL4Packet, ingress: bool, drop_on_error: bool) -> Place:
        Requires(Acc(spkt.State()))
        Requires(Acc(self.State(), 1/2))
        Requires(self.get_topology_mtu() is not None)
        Requires(self.get_interface_to_addr() is not None)
        Requires(spkt.get_path() is not None)
        Requires(spkt.get_addrs() is not None)
        Requires(spkt.get_addrs_dst() is not None)
        Requires(spkt.get_path_iof_idx() is not None)
        Requires(spkt.get_path_hof_idx() is not None)
        Requires(spkt.get_addrs_dst_host() is not None)
        Requires(spkt.get_ext_hdrs_len() == 0)
        Requires(Implies(not ingress,
                         Let(spkt.get_path(), bool, lambda path:
                            Unfolding(Acc(spkt.State(), 1/10),
                                path.get_hof_idx() + 1 < path.get_ofs_len() and
                                isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 1), HopOpaqueField) and
                                path.ofs_get_by_idx(path.get_hof_idx() + 1) is not path.ofs_get_by_idx(path.get_hof_idx())
                         )))
                 )
        Requires(dict_pred(SVC_TO_SERVICE))
        Requires(Unfolding(Acc(spkt.State(), 1 / 10), Let(spkt.path, bool, lambda path:
                    path.get_hof_idx() < path.get_ofs_len() - 1 and
                    Let(cast(HopOpaqueField, Unfolding(Acc(path.State(), 1 / 10), path._ofs.get_by_idx(path._hof_idx + 1))), bool, lambda hof:
                        not path.get_hof_verify_only(hof)) and
                    path.get_hof_idx() - path.get_iof_idx() < path.get_iof_hops(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx()))) and
                    Let(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx())), bool, lambda iof:
                    Implies((Let(cast(HopOpaqueField, path.ofs_get_by_idx(path.get_hof_idx() + 1)), bool, lambda hof:
                        not path.get_hof_xover(hof) or
                        path.get_iof_shortcut(iof)
                     ) and
                    (path.get_hof_idx() != path.get_iof_idx() + path.get_iof_hops(iof))),
                        path.get_hof_idx() + 2 < path.get_ofs_len() and
                        isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField) and
                        path.ofs_get_by_idx(path.get_hof_idx() + 2) is not path.ofs_get_by_idx(path.get_hof_idx() + 1)
                    )
                    ) and
                    Implies(path.get_hof_idx() < path.get_ofs_len() - 2,
                        isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField))))
                 )
        Requires(MustTerminate(self.get_topology_border_routers_len() + 6))
        Ensures(Acc(spkt.State()))
        Ensures(Acc(self.State(), 1/2))
        Ensures(dict_pred(SVC_TO_SERVICE))
        Exsures(SCIONBaseException, Acc(spkt.State()))
        Exsures(SCIONBaseException, Acc(self.State(), 1/2))
        Exsures(SCIONBaseException, dict_pred(SVC_TO_SERVICE))
        Exsures(SCIONBaseException, Acc(RaisedException().args_))
        Exsures(SCIONIFVerificationError, len(RaisedException().args_) == 2)
        Exsures(SCIONOFVerificationError, len(RaisedException().args_) == 2)
        Exsures(SCIONSegmentSwitchError, len(RaisedException().args_) >= 1)
        # Exsures(SCIONBaseException, True)
        # Exsures(SCIONBaseError, Unfolding(Rd(spkt.State()), spkt.path != None))
        # Exsures(SCIONBaseError, Unfolding(Rd(spkt.State()), Unfolding(Rd(spkt.path.State()), not valid_hof(spkt.path))))
        path = spkt.get_path()
        if len(spkt) > self.get_topology_mtu():
            # FIXME(kormat): ignore this check for now, as PCB packets are often
            # over MTU, it's just that udp-overlay handles fragmentation for us.
            # Once we have TCP/SCION, this check should be re-instated.
            # This also needs to look at the specific MTU for the relevant link
            # if on egress.
            #  raise SCMPOversizePkt("Packet larger than mtu", mtu)
            pass
        Unfold(Acc(spkt.State(), 1/4))
        # self.verify_hof(path, ingress=ingress)
        try:
            self.verify_hof(spkt.path, ingress=ingress)
        finally:
            Fold(Acc(spkt.State(), 1/4))
        Unfold(Acc(spkt.State(), 1 / 4))
        hof = spkt.path.get_hof()
        Fold(Acc(spkt.State(), 1/4))
        if spkt.get_path_hof_verify_only(hof):
            raise SCMPNonRoutingHOF
        # FIXME(aznair): Remove second condition once PathCombinator is less
        # stupid.
        spkt_isd_as = spkt.get_addrs_dst_isd_as()
        self_isd_as = self.get_addr_isd_as()
        if ((spkt_isd_as is None and self_isd_as is None) or (spkt_isd_as is not None and self.eq_isd_as(spkt))) and spkt.path_call_is_on_last_segment():
            self.deliver(t, spkt)
            return t
        if ingress:
            Unfold(Acc(spkt.State(), 1 / 10))
            prev_if = path.get_curr_if()
            prev_iof = path.get_iof()
            prev_hof = path.get_hof()
            prev_iof_idx = path.get_of_idxs()[0]
            Fold(Acc(spkt.State(), 1 / 10))
            fwd_if, path_incd, skipped_vo = self._calc_fwding_ingress(spkt)
            Unfold(Acc(spkt.State(), 1 / 10))
            # path = spkt.path # seemingly necessary after call to _calc_fwding_ingress
            cur_iof_idx = path.get_of_idxs()[0]
            if prev_iof_idx != cur_iof_idx:
                try:
                    self._validate_segment_switch(path, fwd_if, prev_if, prev_iof, prev_hof)
                finally:
                    Fold(Acc(spkt.State(), 1/10))
            elif skipped_vo:
                Fold(Acc(spkt.State(), 1 / 10))
                raise SCIONSegmentSwitchError("Skipped verify only field, but "
                                              "did not switch segments.")
            else:
                Fold(Acc(spkt.State(), 1 / 10))
        else:
            Unfold(Acc(spkt.State(), 1 / 10))
            fwd_if = path.get_fwd_if()
            Fold(Acc(spkt.State(), 1 / 10))
            path_incd = False
        if Unfolding(Acc(self.State(), 1/10), self.ifid2br.__contains__(fwd_if)):
            # br = self.ifid2br[fwd_if]
            br = self.get_ifid2br_elem(fwd_if)
            if_addr, port = self.get_br_addr(br), self.get_br_port(br)
            # if_addr, port = br.addr, br.port
        # except KeyError:
        else:
            # So that the error message will show the current state of the
            # packet.
            spkt.update()
            logging.error("Cannot forward packet, fwd_if is invalid (%s):\n%s",
                          fwd_if, spkt)
            raise SCMPBadIF(fwd_if) from None
        # if not self.if_states[fwd_if].is_active:
        if not self.get_if_states_elem_is_active(fwd_if):
            if drop_on_error:
                logging.debug("IF is down, but drop_on_error is set, dropping")
                return t
            self.send_revocation(t, spkt, fwd_if, ingress, path_incd)
            return t
        if ingress:
            logging.debug("Sending to IF %s (%s:%s)", fwd_if, if_addr, port)
            return self.send(t, spkt, if_addr, port)
        else:
            Unfold(Acc(spkt.State()))
            path.inc_hof_idx()
            Fold(Acc(spkt.State()))
            return self._egress_forward(t, spkt)

    def _validate_segment_switch(self, path: SCIONPath, fwd_if: int, prev_if: int,
                                 prev_iof: InfoOpaqueField,
                                 prev_hof: HopOpaqueField) -> None:
        Requires(Acc(path.State(), 1/10))
        Requires(Acc(self.State(), 1/10))
        Requires(path.get_iof_idx() is not None)
        Requires(path.get_hof_idx() is not None)
        Requires(prev_iof in path.get_ofs_contents())
        Requires(prev_hof in path.get_ofs_contents())
        Requires(MustTerminate(self.get_topology_border_routers_len() + 5))
        Ensures(Acc(path.State(), 1/10))
        Ensures(Acc(self.State(), 1/10))
        Exsures(SCIONSegmentSwitchError, Acc(path.State(), 1/10))
        Exsures(SCIONSegmentSwitchError, Acc(self.State(), 1/10))
        Exsures(SCIONSegmentSwitchError, Acc(RaisedException().args_))
        Exsures(SCIONSegmentSwitchError, len(RaisedException().args_) >= 1)
        """
        Validates switching of segments according to the following rules:

        1) Never switch from a down-segment to an up-segment
           (valley-freeness)
        2) Never switch from an up(down)-segment to an up(down)-segment, if the
           packet is not forwarded(received) over a ROUTING link.
        3) Never switch from a core-segment to a core-segment.
        4) If a packet is received over a peering link, check on ingress that
           the egress IF is the same for both the current and next hop fields.
        5) If a packet is to be forwarded over a peering link, check on ingress
           that the ingress IF is the same for both current and next hop fields.
        """
        rcvd_on_link_type = self._link_type(prev_if)
        fwd_on_link_type = self._link_type(fwd_if)
        cur_iof = path.get_iof()
        cur_hof = path.get_hof()
        if not path.get_iof_up_flag(prev_iof) and path.get_iof_up_flag(cur_iof):
            raise SCIONSegmentSwitchError(
                "Switching from down- to up-segment is not allowed.")
        if (path.get_iof_up_flag(prev_iof) and path.get_iof_up_flag(cur_iof) and
                (fwd_on_link_type is not None and fwd_on_link_type != LinkType.ROUTING)):
            raise SCIONSegmentSwitchError(
                "Switching from up- to up-segment is not allowed "
                "if the packet is not forwarded over a ROUTING link.")
        if (not path.get_iof_up_flag(prev_iof) and not path.get_iof_up_flag(cur_iof) and
                (rcvd_on_link_type is not None and rcvd_on_link_type != LinkType.ROUTING)):
            raise SCIONSegmentSwitchError(
                "Switching from down- to down-segment is not "
                "allowed if the packet was not received over a ROUTING link.")
        if ((rcvd_on_link_type is not None and rcvd_on_link_type == LinkType.ROUTING) and
                (fwd_on_link_type is not None and fwd_on_link_type == LinkType.ROUTING)):
            raise SCIONSegmentSwitchError(
                "Switching from core- to core-segment is not allowed.")
        if (((rcvd_on_link_type is not None and rcvd_on_link_type == LinkType.PEER) or
             (fwd_on_link_type is not None and fwd_on_link_type == LinkType.PEER)) and
                    path.get_hof_egress_if(prev_hof) != path.get_hof_egress_if(cur_hof)):
            raise SCIONSegmentSwitchError(
                "Egress IF of peering HOF does not match egress IF of current "
                "HOF.")

    def _calc_fwding_ingress(self, spkt: SCIONL4Packet) -> Tuple[int, bool, bool]:
        Requires(Acc(spkt.State()))
        Requires(spkt.get_path() is not None)
        Requires(spkt.get_path_iof_idx() is not None)
        Requires(spkt.get_path_hof_idx() is not None)
        Requires(spkt.get_ext_hdrs_len() == 0)
        Requires(Unfolding(Acc(spkt.State(), 1/10), Let(spkt.path, bool, lambda path:
                path.get_hof_idx() < path.get_ofs_len() - 1 and
                Let(cast(HopOpaqueField, Unfolding(Acc(path.State(), 1/10), path._ofs.get_by_idx(path._hof_idx + 1))), bool, lambda hof:
                    not path.get_hof_verify_only(hof)) and
                path.get_hof_idx() - path.get_iof_idx() < path.get_iof_hops(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx()))) and
                Let(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx())), bool, lambda iof:
                        Implies((Let(cast(HopOpaqueField, path.ofs_get_by_idx(path.get_hof_idx() + 1)), bool, lambda hof:
                                    not path.get_hof_xover(hof) or
                                    path.get_iof_shortcut(iof)
                                    ) and
                                    (path.get_hof_idx() != path.get_iof_idx() + path.get_iof_hops(iof))),
                                path.get_hof_idx() + 2 < path.get_ofs_len() and
                                isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField) and
                                path.ofs_get_by_idx(path.get_hof_idx() + 2) is not path.ofs_get_by_idx(path.get_hof_idx() + 1)
                                )
                    ) and
                Implies(path.get_hof_idx() < path.get_ofs_len() - 2, isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField)))))
        Requires(MustTerminate(3))
        Ensures(Acc(spkt.State()))
        Ensures(spkt.get_path() is not None)
        Ensures(spkt.get_path_iof_idx() is not None)
        Ensures(spkt.get_path_hof_idx() is not None)
        Ensures(spkt.get_ext_hdrs_len() == 0)
        Ensures(spkt.get_path_ofs_contents() is Old(spkt.get_path_ofs_contents()))
        Ensures(spkt.get_path() is Old(spkt.get_path()))
        Unfold(Acc(spkt.State(), 1/10))
        path = spkt.path
        hof = path.get_hof()
        incd = False
        skipped_vo = False
        path_hof_xover = path.get_hof_xover(hof)
        Fold(Acc(spkt.State(), 1 / 10))
        if path_hof_xover:
            Unfold(Acc(spkt.State()))
            skipped_vo = path.inc_hof_idx()
            Fold(Acc(spkt.State()))
            incd = True
        Unfold(Acc(spkt.State(), 1 / 10))
        result = path.get_fwd_if(), incd, skipped_vo
        Fold(Acc(spkt.State(), 1 / 10))
        return result

    def _link_type(self, if_id: int) -> Optional[str]:
        Requires(Acc(self.State(), 1/10))
        Requires(MustTerminate(self.get_topology_border_routers_len() + 4))
        Ensures(Acc(self.State(), 1/10))
        Ensures(self.get_topology_border_routers_len() == Old(self.get_topology_border_routers_len()))
        """
        Returns the link type of the link corresponding to 'if_id' or None.
        """
        Unfold(Acc(self.State(), 1/20))
        border_router = self.topology.get_all_border_routers()
        Fold(Acc(self.State(), 1/20))
        border_router_len = len(border_router)
        border_router_enum = enumerate(border_router)
        for i, br in border_router_enum:
            Invariant(Acc(self.State(), 1/10))
            Invariant(Acc(list_pred(border_router), 1/20))
            Invariant(border_router_len == len(border_router))
            Invariant(len(border_router) == self.get_topology_border_routers_len())
            Invariant(Forall(border_router, lambda x: (x in self.get_topology_border_routers(), [[x in border_router]])))
            Invariant(Forall(border_router_enum, lambda x: (x[1] in border_router)))
            Invariant(MustTerminate(self.get_topology_border_routers_len() - i + 3))
            if self.get_br_interface_if_id(br) == if_id:
                return self.get_br_interface_link_type(br)
        return None

    def _needs_local_processing(self, pkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(Acc(pkt.State(), 1/10))
        Requires(pkt.get_addrs() is not None)
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10))
        Ensures(Acc(pkt.State(), 1/10))
        return pkt.get_addrs_dst() in [
            self.get_addr(),
            SCIONAddr.from_values(self.get_addr_isd_as(),
                                  self.get_interface_addr()),
        ]

    def _process_flags(self, flags: List[Tuple[int, ...]], pkt: SCIONL4Packet, from_local_as: bool) -> Tuple[bool, bool]:
        """
        Go through the flags set by hop-by-hop extensions on this packet.
        :returns:
        """
        Requires(Acc(list_pred(flags), 1/9))
        Requires(len(flags) == 0)
        Requires(MustTerminate(2))
        Ensures(Acc(list_pred(flags), 1/9))
        Ensures(not Result()[1])
        process = False
        # First check if any error or no_process flags are set
        for (flag, *args) in flags:
            Invariant(len(flags) == 0)
            Invariant(MustTerminate(1))
            if flag == RouterFlag.ERROR:
                logging.error("%s", args[0])
                return True, False
            elif flag == RouterFlag.NO_PROCESS:
                return True, False
        # Now check for other flags
        for (flag, *args) in flags:
            Invariant(len(flags) == 0)
            Invariant(process == False)
            Invariant(MustTerminate(1))
            if flag == RouterFlag.FORWARD:
                if from_local_as:
                    self._process_fwd_flag(pkt)
                else:
                    self._process_fwd_flag(pkt, args[0])
                return True, False
            elif flag in (RouterFlag.DELIVER, RouterFlag.FORCE_DELIVER):
                self._process_deliver_flag(pkt, flag)
                return True, False
            elif flag == RouterFlag.PROCESS_LOCAL:
                process = True
        return False, process

    def _process_fwd_flag(self, pkt: SCIONL4Packet, ifid: int=None) -> None:
        Requires(False)
        # if ifid is None:
        #     logging.debug("Packet forwarded over link by extension")
        #     self._egress_forward(pkt)
        #     return
        # if ifid == 0:
        #     logging.error("Extension asked to forward this to interface 0:\n%s",
        #                   pkt)
        #     return
        # next_hop = self.ifid2br[ifid]
        # logging.debug("Packet forwarded by extension via %s:%s",
        #               next_hop.addr, next_hop.port)
        # self.send(pkt, next_hop.addr, next_hop.port)

    def _process_deliver_flag(self, pkt: SCIONL4Packet, flag: int) -> None:
        Requires(False)
        # if (flag == RouterFlag.DELIVER and
        #         pkt.addrs.dst.isd_as != self.addr.isd_as):
        #     logging.error("Extension tried to deliver this locally, but this "
        #                   "is not the destination ISD-AS:\n%s", pkt)
        #     return
        # logging.debug("Packet delivered by extension")
        # self.deliver(pkt)

    # def _get_msg_meta(self, packet, addr, sock):
    #     meta = RawMetadata.from_values(packet, addr, sock == self._udp_sock)
    #     return packet, meta
    #
    # def handle_msg_meta(self, msg, meta):
    #     """
    #     Main routine to handle incoming SCION messages.
    #     """
    #     self.handle_request(meta.packet, meta.addr, meta.from_local_as)

    def handle_request(self, t: Place, packet: bytes, _: object, from_local_socket: bool = True, sock: object = None) -> Place:
        Requires(Acc(self.State(), 1 / 2))
        Requires(self.get_topology_mtu() is not None)
        Requires(self.get_interface_to_addr() is not None)
        Requires(dict_pred(SVC_TO_SERVICE))
        Requires(MustTerminate(self.get_topology_border_routers_len() + 8))
        Ensures(Acc(self.State(), 1/2))
        Ensures(dict_pred(SVC_TO_SERVICE))
        Exsures(SCIONBaseException, Acc(self.State(), 1/2))
        Exsures(SCIONBaseException, dict_pred(SVC_TO_SERVICE))
        """
        Main routine to handle incoming SCION packets.

        :param bytes packet: The incoming packet to handle.
        :param tuple sender: Tuple of sender IP, port.
        :param bool from_local_socket:
            True, if the packet was received on the local socket.
        """
        from_local_as = from_local_socket
        pkt = self._parse_packet(packet, from_local_as)
        if not pkt:
            return t
        try:
            flags = self.handle_extensions(pkt, True, from_local_as)
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
            return t
        stop, needs_local = self._process_flags(flags, pkt, from_local_as)
        if stop:
            logging.debug("Stopped processing")
            return t
        try:
            needs_local = needs_local or self._needs_local_processing(pkt)
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
            return t
        if needs_local:
            try:
                pkt.parse_payload()
            except SCIONBaseError:
                log_exception("Error parsing payload:\n%s" % hex_str(packet))
                return t
            handler = False  # self._get_handler(pkt)
        else:
            # It's a normal packet, just forward it.
            handler = True # self.handle_data
        logging.debug("handle_request (from_local_as? %s):"
                      "\n  %s\n  %s\n  handler: %s",
                      from_local_as, pkt.get_cmn_hdr(), pkt.get_addrs(), handler)
        if not handler:
            return t
        try:
            return self.handle_data(t, pkt, from_local_as)
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)
        return t

    """
    Start of performance helper functions
    """

    @Pure
    def get_topology_mtu(self) -> Optional[int]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.get_topology_mtu_1())

    @Pure
    def get_topology_mtu_1(self) -> Optional[int]:
        Requires(Acc(self.topology, 1/10))
        Requires(Acc(self.topology.State(), 1/10))
        return Unfolding(Acc(self.topology.State(), 1/10), self.topology.mtu)

    @Pure
    def get_topology_border_routers(self) -> Sequence[RouterElement]:
        Requires(Acc(self.State(), 1/20))
        return Unfolding(Acc(self.State(), 1/20), self.get_topology_border_routers_1())

    @Pure
    def get_topology_border_routers_1(self) -> Sequence[RouterElement]:
        Requires(Acc(self.topology, 1/20))
        Requires(Acc(self.topology.State(), 1/20))
        return Unfolding(Acc(self.topology.State(), 1/20), self.topology.border_routers())

    @Pure
    def get_interface_if_id(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.get_interface_if_id_1())

    @Pure
    def get_interface_if_id_1(self) -> int:
        Requires(Acc(self.interface, 1/10))
        Requires(Acc(self.interface.State(), 1/10))
        return Unfolding(Acc(self.interface.State(), 1/10), self.interface.if_id)

    @Pure
    def get_addr_isd_as(self) -> Optional[ISD_AS]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.get_addr_isd_as_1())

    @Pure
    def get_addr_isd_as_1(self) -> Optional[ISD_AS]:
        Requires(Acc(self.addr, 1/10))
        Requires(Acc(self.addr.State(), 1/10))
        return Unfolding(Acc(self.addr.State(), 1 / 10), self.addr.isd_as)

    @Pure
    def get_interface_to_addr(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10),  self.get_interface_to_addr_1())

    @Pure
    def get_interface_to_addr_1(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.interface, 1/10))
        Requires(Acc(self.interface.State(), 1/10))
        return Unfolding(Acc(self.interface.State(), 1/10), self.interface.to_addr)

    @Pure
    def get_interface_addr(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.State(), 1 / 10))
        return Unfolding(Acc(self.State(), 1 / 10), self.get_interface_addr_1())

    @Pure
    def get_interface_addr_1(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.interface, 1 / 10))
        Requires(Acc(self.interface.State(), 1 / 10))
        return Unfolding(Acc(self.interface.State(), 1 / 10), self.interface.addr)

    @Pure
    def get_interface_to_udp_port(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.get_interface_to_udp_port_1())

    @Pure
    def get_interface_to_udp_port_1(self) -> int:
        Requires(Acc(self.interface, 1/10))
        Requires(Acc(self.interface.State(), 1/10))
        return Unfolding(Acc(self.interface.State(), 1/10), self.interface.to_udp_port)

    @Pure
    def get_pre_ext_handlers(self) -> Dict[Optional[int], bool]:
        Requires(Acc(self.State(), 1 / 10))
        return Unfolding(Acc(self.State(), 1/10), self.pre_ext_handlers)

    @Pure
    def get_post_ext_handlers(self) -> Dict[Optional[int], bool]:
        Requires(Acc(self.State(), 1 / 10))
        return Unfolding(Acc(self.State(), 1 / 10), self.post_ext_handlers)

    @Pure
    def get_of_gen_key(self) -> bytes:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.of_gen_key)

    @Pure
    def get_addr(self) -> SCIONAddr:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.addr)

    @Pure
    def get_topology_border_routers_len(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Ensures(Result() == Unfolding(Acc(self.State(), 1/10), len(self.topology.get_border_routers())))
        Ensures(Result() >= 0)
        return Unfolding(Acc(self.State(), 1/10), self.get_topology_border_routers_len_1())

    @Pure
    def get_topology_border_routers_len_1(self) -> int:
        Requires(Acc(self.topology, 1/10))
        Requires(Acc(self.topology.State(), 1/10))
        Ensures(Result() >= 0)
        return Unfolding(Acc(self.topology.State(), 1/10), len(self.topology.border_routers()))

    @Pure
    def get_br_interface_if_id(self, br: RouterElement) -> int:
        Requires(Acc(self.State(), 1/20))
        Requires(br in self.get_topology_border_routers())
        return Unfolding(Acc(self.State(), 1/20), self.get_br_interface_if_id_1(br))

    @Pure
    def get_br_interface_if_id_1(self, br: RouterElement) -> int:
        Requires(Acc(self.topology, 1/20))
        Requires(Acc(self.topology.State(), 1/20))
        Requires(br in self.get_topology_border_routers_1())
        return Unfolding(Acc(self.topology.State(), 1/20), br.get_interface_if_id())

    @Pure
    def get_br_interface_link_type(self, br: RouterElement) -> Optional[str]:
        Requires(Acc(self.State(), 1/20))
        Requires(br in self.get_topology_border_routers())
        return Unfolding(Acc(self.State(), 1/20), self.get_br_interface_link_type_1(br))

    @Pure
    def get_br_interface_link_type_1(self, br: RouterElement) -> Optional[str]:
        Requires(Acc(self.topology, 1/20))
        Requires(Acc(self.topology.State(), 1 / 20))
        Requires(br in self.get_topology_border_routers_1())
        return Unfolding(Acc(self.topology.State(), 1 / 20), br.get_interface_link_type())

    @Pure
    def eq_isd_as(self, spkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(Acc(spkt.State(), 1 / 10))
        Requires(spkt.get_addrs() is not None)
        Requires(spkt.get_addrs_dst() is not None)
        Requires(spkt.get_addrs_dst_isd_as() is not None)
        return Unfolding(Acc(spkt.State(), 1 / 10), self.eq_isd_as_1(spkt))

    @Pure
    def eq_isd_as_1(self, spkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.State(), 1 / 10))
        Requires(Acc(spkt.addrs, 1 / 10))
        Requires(Acc(spkt.addrs.State(), 1 / 10))
        Requires(spkt.get_addrs_dst_1() is not None)
        Requires(spkt.get_addrs_dst_isd_as_1() is not None)
        return Unfolding(Acc(spkt.addrs.State(), 1 / 10), self.eq_isd_as_2(spkt))

    @Pure
    def eq_isd_as_2(self, spkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.State(), 1 / 10))
        Requires(Acc(spkt.addrs, 1 / 10))
        Requires(Acc(spkt.addrs.dst, 1 / 10))
        Requires(Acc(spkt.addrs.dst.State(), 1 / 10))
        Requires(spkt.get_addrs_dst_isd_as_2() is not None)
        return Unfolding(Acc(spkt.addrs.dst.State(), 1 / 10), self.eq_isd_as_3(spkt))

    @Pure
    def eq_isd_as_3(self, spkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.State(), 1 / 10))
        Requires(Acc(spkt.addrs, 1 / 10))
        Requires(Acc(spkt.addrs.dst, 1 / 10))
        Requires(Acc(spkt.addrs.dst.isd_as, 1 / 10))
        Requires(Acc(spkt.addrs.dst.isd_as.State(), 1 / 10))
        Requires(spkt.addrs.dst.isd_as is not None)
        return Unfolding(Acc(self.State(), 1 / 10), self.eq_isd_as_4(spkt))

    @Pure
    def eq_isd_as_4(self, spkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.addr, 1/10))
        Requires(Acc(self.addr.State(), 1 / 10))
        Requires(Acc(spkt.addrs, 1 / 10))
        Requires(Acc(spkt.addrs.dst, 1 / 10))
        Requires(Acc(spkt.addrs.dst.isd_as, 1 / 10))
        Requires(Acc(spkt.addrs.dst.isd_as.State(), 1 / 10))
        Requires(spkt.addrs.dst.isd_as is not None)
        return Unfolding(Acc(self.addr.State(), 1 / 10), spkt.addrs.dst.isd_as == self.addr.isd_as)

    @Pure
    def get_ifid2br(self) -> Dict[int, RouterElement]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.ifid2br)

    @Pure
    @ContractOnly
    def get_ifid2br_elem(self, fwd_if: int) -> RouterElement:
        Requires(Acc(self.State(), 1/10))
        Requires(Unfolding(Acc(self.State(), 1/10), self.ifid2br.__contains__(fwd_if)))
        Ensures(Result() in self.get_topology_border_routers())
        return Unfolding(Acc(self.State(), 1/10), self.ifid2br[fwd_if])

    @Pure
    @ContractOnly
    def get_if_states_elem_is_active(self, fwd_if: int) -> bool:
        Requires(Acc(self.State(), 1 / 10))
        # Requires(Unfolding(Acc(self.State(), 1/10), self.if_states.__contains__(fwd_if)))
        return Unfolding(Acc(self.State(), 1 / 10), self.get_if_states_elem_is_active_1(cast(InterfaceState, self.if_states[fwd_if])))

    @Pure
    def get_if_states_elem_is_active_1(self, if_state: InterfaceState) -> bool:
        Requires(Acc(if_state.State(), 1 / 10))
        return Unfolding(Acc(if_state.State(), 1 / 10), if_state.is_active)

    # @Pure
    # def get_ifid2br_elem_1(self, fwd_if: int) -> RouterElement:
    #     Requires(Acc(self.ifid2br, 1/10))
    #     Requires(Acc(self.topology, 1/10))
    #     Requires(Acc(self.topology.State(), 1/10))
    #     Requires(Acc(dict_pred(self.ifid2br), 1/10))
    #     Requires(self.ifid2br.__contains__(fwd_if))
    #     Ensures(Result() in self.topology.get_border_routers())
    #     return self.ifid2br[fwd_if]

    @Pure
    def get_br_addr(self, br: RouterElement) -> Optional[HostAddrBase]:
        Requires(Acc(self.State(), 1/10))
        Requires(br in self.get_topology_border_routers())
        Ensures(br in self.get_topology_border_routers())
        Ensures(Result() is not None)
        return Unfolding(Acc(self.State(), 1 / 10), self.get_br_addr_1(br))

    @Pure
    def get_br_addr_1(self, br: RouterElement) -> Optional[HostAddrBase]:
        Requires(Acc(self.topology, 1/10))
        Requires(Acc(self.topology.State(), 1 / 10))
        Requires(br in self.topology.get_border_routers())
        Ensures(br in self.topology.get_border_routers())
        Ensures(Result() is not None)
        return Unfolding(Acc(self.topology.State(), 1 / 10), self.get_br_addr_2(br))

    @Pure
    def get_br_addr_2(self, br: RouterElement) -> Optional[HostAddrBase]:
        Requires(Acc(self.topology, 1/10))
        Requires(Acc(self.topology.parent_border_routers, 1 / 20))
        Requires(Acc(self.topology.child_border_routers, 1 / 20))
        Requires(Acc(self.topology.peer_border_routers, 1 / 20))
        Requires(Acc(self.topology.routing_border_routers, 1 / 20))
        Requires(Forall(self.topology.border_routers(), lambda e: (Acc(e.State(), 1/10))))
        Requires(Forall(self.topology.border_routers(), lambda e: (e.get_addr() is not None)))
        Requires(br in self.topology.border_routers())
        Ensures(br in self.topology.border_routers())
        Ensures(Result() is not None)
        return Unfolding(Acc(br.State(), 1 / 10), br.addr)

    @Pure
    def get_br_port(self, br: RouterElement) -> Optional[int]:
        Requires(Acc(self.State(), 1 / 10))
        Requires(br in self.get_topology_border_routers())
        Ensures(br in self.get_topology_border_routers())
        Ensures(Result() is not None)
        return Unfolding(Acc(self.State(), 1 / 10), self.get_br_port_1(br))

    @Pure
    def get_br_port_1(self, br: RouterElement) -> Optional[int]:
        Requires(Acc(self.topology, 1 / 10))
        Requires(Acc(self.topology.State(), 1 / 10))
        Requires(br in self.topology.get_border_routers())
        Ensures(br in self.topology.get_border_routers())
        Ensures(Result() is not None)
        return Unfolding(Acc(self.topology.State(), 1 / 10), self.get_br_port_2(br))

    @Pure
    def get_br_port_2(self, br: RouterElement) -> Optional[int]:
        Requires(Acc(self.topology, 1 / 10))
        Requires(Acc(self.topology.parent_border_routers, 1 / 20))
        Requires(Acc(self.topology.child_border_routers, 1 / 20))
        Requires(Acc(self.topology.peer_border_routers, 1 / 20))
        Requires(Acc(self.topology.routing_border_routers, 1 / 20))
        Requires(Forall(self.topology.border_routers(), lambda e: (Acc(e.State(), 1 / 10))))
        Requires(Forall(self.topology.border_routers(), lambda e: (e.get_port() is not None)))
        Requires(br in self.topology.border_routers())
        Ensures(br in self.topology.border_routers())
        Ensures(Result() is not None)
        return Unfolding(Acc(br.State(), 1 / 10), br.port)

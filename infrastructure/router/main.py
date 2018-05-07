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
    SCIONServiceLookupError,
)
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
from lib.packet.scion_addr import SCIONAddr
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
from typing import List, Tuple, Union, Callable, cast, Optional, Dict, Any
from lib.packet.scion import SCIONL4Packet, packed
from lib.packet.host_addr import HostAddrBase
from lib.util import Raw
from lib.topology import InterfaceElement


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
        # self.pre_ext_handlers = {
        #     SibraExtBase.EXT_TYPE: self.handle_sibra,
        #     TracerouteExt.EXT_TYPE: self.handle_traceroute,
        #     OneHopPathExt.EXT_TYPE: self.handle_one_hop_path,
        #     ExtHopByHopType.SCMP: self.handle_scmp,
        # }
        # self.post_ext_handlers = {
        #     SibraExtBase.EXT_TYPE: False, TracerouteExt.EXT_TYPE: False,
        #     ExtHopByHopType.SCMP: False, OneHopPathExt.EXT_TYPE: False,
        # }
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
        return Acc(self.interface) and self.interface.State() and Acc(self._remote_sock) and Acc(self._udp_sock) and Acc(self.of_gen_key)

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
        Unfold(Acc(self.State(), 1 / 9))
        from_local_as = dst == Unfolding(Acc(self.interface.State(), 1/11), self.interface.to_addr)
        self.handle_extensions(packet, False, from_local_as)
        if from_local_as:
            result = self._remote_sock.send(t, packet.pack(), (str(dst), dst_port))
        else:
            result = self._udp_sock.send(t, packet.pack(), (str(dst), dst_port))
        Fold(Acc(self.State(), 1 / 9))
        return result[1]

    def handle_extensions(self, spkt: SCIONL4Packet, pre_routing_phase: bool, from_local_as: bool) -> List[Tuple[int, ...]]:
        """
        Handle SCION Packet extensions. Handlers can be defined for pre- and
        post-routing.
        """
        #Requires(MustTerminate(2))
        Requires(Acc(spkt.State(), 1/9))
        Requires(Unfolding(Acc(spkt.State(), 1/100), len(spkt.ext_hdrs) == 0))
        Ensures(Acc(list_pred(Result())))
        Ensures(Acc(spkt.State(), 1 / 9))
        Ensures(len(Result()) == 0)
        if pre_routing_phase:
            prefix = "pre"
            # handlers = self.pre_ext_handlers  #type: Union[Dict[int, function], Dict[int, bool]]## type: Union[Dict[int, bool], Dict[int, Callable[[object, object, object], list]]]
        else:
            prefix = "post"
            # handlers = self.post_ext_handlers
        flags = []  # type: List[Tuple[int, ...]]
        # Hop-by-hop extensions must be first (just after path), and process
        # only MAX_HOPBYHOP_EXT number of them. If an SCMP ext header is
        # present, it must be the first hopbyhop extension (and isn't included
        # in the MAX_HOPBYHOP_EXT check).
        Unfold(Acc(spkt.State(), 1/9))
        count = 0
        ext_hdrs = spkt.ext_hdrs
        for i, ext_hdr in enumerate(ext_hdrs):
            #Invariant(Acc(spkt.ext_hdrs, 1/1000))
            #Invariant(Acc(list_pred(ext_hdrs), 1/1000))
            Invariant(len(ext_hdrs) == 0)
            assert False
            # if ext_hdr.EXT_CLASS != ExtensionClass.HOP_BY_HOP:
            #     break
            # if ext_hdr.EXT_TYPE == ExtHopByHopType.SCMP:
            #     if i != 0:
            #         logging.error("SCMP ext header not first.")
            #         raise SCMPBadExtOrder(i)
            # else:
            #     count += 1
            # if count > MAX_HOPBYHOP_EXT:
            #     logging.error("Too many hop-by-hop extensions.")
            #     raise SCMPTooManyHopByHop(i)
            # handler = handlers.get(ext_hdr.EXT_TYPE) # type: Optional[Union[function, bool]]
            # if handler is None:
            #     logging.debug("No %s-handler for extension type %s",
            #                   prefix, ext_hdr.EXT_TYPE)
            #     raise SCMPBadHopByHop
            # if handler:
            #     flags.extend(cast(Callable[[object, object, object], list], handler)(ext_hdr, spkt, from_local_as))
        Fold(Acc(spkt.State(), 1 / 9))
        return flags

    # def handle_traceroute(self, hdr: TracerouteExt, spkt: SCIONL4Packet, _: bool) -> List[Tuple[int, str]]:
    #     hdr.append_hop(self.addr.isd_as, self.interface.if_id)
    #     return []
    #
    # def handle_one_hop_path(self, hdr: ExtensionHeader, spkt: SCIONL4Packet, from_local_as: bool) -> List[Tuple[int]]:
    #     if len(spkt.path) != InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN:
    #         logging.error("OneHopPathExt: incorrect path length.")
    #         return [(RouterFlag.ERROR,)]
    #     if not from_local_as:  # Remote packet, create the 2nd Hop Field
    #         info = spkt.path.get_iof() # type: Optional[InfoOpaqueField]
    #         hf1 = spkt.path.get_hof_ver(ingress=True)
    #         exp_time = OneHopPathExt.HOF_EXP_TIME
    #         hf2 = HopOpaqueField.from_values(exp_time, self.interface.if_id, 0)
    #         hf2.set_mac(self.of_gen_key, info.timestamp, hf1)
    #         # FIXME(PSz): quite brutal for now:
    #         spkt.path = SCIONPath.from_values(info, [hf1, hf2])
    #         spkt.path.inc_hof_idx()
    #     return []
    #
    # def handle_sibra(self, hdr: SibraExtBase, spkt: SCIONL4Packet, from_local_as: bool) -> List[Tuple[int, str]]:
    #     ret = hdr.process(self.sibra_state, spkt, from_local_as,
    #                       self.sibra_key)
    #     logging.debug("Sibra state:\n%s", self.sibra_state)
    #     return ret
    #
    # def handle_scmp(self, hdr: SCMPExt, spkt: SCIONL4Packet, _: bool) -> List[Tuple[int]]:
    #     if hdr.hopbyhop:
    #         return [(RouterFlag.PROCESS_LOCAL,)]
    #     return []

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
        """
        For a given service return a server address. Guarantee that all packets
        from the same source to a given service are sent to the same server.

        :param str service: Service to query for.
        :type pkt: :class:`lib.packet.scion.SCIONBasePacket`

        """
        # addrs = self.dns_query_topo(service)
        # addrs.sort()  # To not rely on order of DNS replies.
        # return addrs[zlib.crc32(pkt.addrs.pack()) % len(addrs)][0]

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
    def send_revocation(self, spkt: SCIONL4Packet, if_id: int, ingress: bool, path_incd: bool) -> None:
        Requires(False)
        """
        Sends an interface revocation for 'if_id' along the path in 'spkt'.
        """
    #     logging.info("Interface %d is down. Issuing revocation.", if_id)
    #     # Check that the interface is really down.
    #     if_state = self.if_states[if_id]
    #     if self.if_states[if_id].is_active:
    #         logging.error("Interface %d appears to be up. Not sending " +
    #                       "revocation." % if_id)
    #         return
    #
    #     assert if_state.rev_info, "Revocation token missing."
    #
    #     rev_pkt = spkt.reversed_copy()
    #     rev_pkt.convert_to_scmp_error(
    #         self.addr, SCMPClass.PATH, SCMPPathClass.REVOKED_IF, spkt, if_id,
    #         ingress, if_state.rev_info.copy(), hopbyhop=True)
    #     if path_incd:
    #         rev_pkt.path.inc_hof_idx()
    #     rev_pkt.update()
    #     logging.debug("Revocation Packet:\n%s" % rev_pkt.short_desc())
    #     # FIXME(kormat): In some circumstances, this doesn't actually work, as
    #     # handle_data will try to send the packet to this interface first, and
    #     # then drop the packet as the interface is down.
    #     self.handle_data(rev_pkt, ingress, drop_on_error=True)

    def deliver(self, t: Place, spkt: SCIONL4Packet, force: bool=True) -> None:
        """
        Forwards the packet to the end destination within the current AS.
        #     :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param bool force:
            If set, allow packets to be delivered locally that would otherwise
            be disallowed.
        """
        # if not force and spkt.addrs.dst.isd_as != self.addr.isd_as:
        #     logging.error("Tried to deliver a non-local packet:\n%s", spkt)
        #     raise SCMPDeliveryNonLocal
        # if len(spkt.path):
        #     hof = spkt.path.get_hof()
        #     if not force and hof.forward_only:
        #         raise SCMPDeliveryFwdOnly
        #     if hof.verify_only:
        #         raise SCMPNonRoutingHOF
        # # Forward packet to destination.
        # addr = spkt.addrs.dst.host
        # if addr.TYPE == AddrType.SVC:
        #     # Send request to any server.
        #     try:
        #         service = SVC_TO_SERVICE[addr.addr]
        #         addr = self.get_srv_addr(service, spkt)
        #     except SCIONServiceLookupError as e:
        #         logging.error("Unable to deliver path mgmt packet: %s", e)
        #         raise SCMPUnknownHost
        # self.send(t, spkt, addr, SCION_UDP_EH_DATA_PORT)

    def verify_hof(self, path: SCIONPath, ingress: bool = True) -> None:
        Requires(Acc(path.State(), 1 / 9))
        Requires(Acc(self.State(), 1 / 9))
        Requires(Unfolding(Acc(path.State(), 1/10), isinstance(path._iof_idx, int)))
        Requires(Unfolding(Acc(path.State(), 1/10), isinstance(path._hof_idx, int)))
        Ensures(Acc(path.State(), 1 / 9))
        Ensures(Acc(self.State(), 1 / 9))
        Ensures(valid_hof(path))
        Exsures(SCIONBaseError, Acc(path.State(), 1 / 9))
        Exsures(SCIONBaseError, Acc(self.State(), 1 / 9))
        #Exsures(SCIONBaseError, not valid_hof(path))
        """Verify freshness and authentication of an opaque field."""
        iof = path.get_iof()
        ts = Unfolding(Acc(path.State(), 1/10), Unfolding(Acc(path._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.timestamp)))
        hof = path.get_hof()
        prev_hof = path.get_hof_ver(ingress=ingress)
        # Check that the interface in the current hop field matches the
        # interface in the router.
        Unfold(Acc(self.State(), 1/10))
        if path.get_curr_if(ingress=ingress) != Unfolding(Acc(self.interface.State(), 1/10), self.interface.if_id):
            #Fold(Acc(iof.State(), 1 / 10))
            Fold(Acc(self.State(), 1 / 10))
            raise SCIONIFVerificationError(hof, iof)

        # Assert(Implies(prev_hof is not None, Acc(prev_hof.State(), 1/10)))
        if int(SCIONTime.get_time()) <= ts + Unfolding(Acc(path.State(), 1/10), Unfolding(Acc(path._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.exp_time))) * EXP_TIME_UNIT:
            if not Unfolding(Acc(path.State(), 1/10), Unfolding(Acc(path._ofs.State(), 1/10), hof.verify_mac(self.of_gen_key, ts, prev_hof))):
                # Fold(Acc(iof.State(), 1 / 10))
                Fold(Acc(self.State(), 1 / 10))
                raise SCIONOFVerificationError(hof, prev_hof)
        else:
            #Fold(Acc(iof.State(), 1 / 10))
            Fold(Acc(self.State(), 1 / 10))
            raise SCIONOFExpiredError(hof)
        #Fold(Acc(iof.State(), 1 / 10))
        Fold(Acc(self.State(), 1 / 10))

    def _egress_forward(self, t: Place, spkt: SCIONL4Packet) -> Place:
        logging.debug("Forwarding to remote interface: %s:%s",
                      self.interface.to_addr, self.interface.to_udp_port)
        self.send(t, spkt, self.interface.to_addr, self.interface.to_udp_port)

    def handle_data(self, t: Place, spkt: SCIONL4Packet, from_local_as: bool, drop_on_error: bool=False) -> Place:
        Requires(Acc(spkt.State(), 1/2))
        Requires(Acc(self.State(), 1/2))
        Requires(Unfolding(Acc(spkt.State(), 1/2), spkt.path is not None))
        Requires(Unfolding(Rd(self.State()), Unfolding(Rd(self.topology.State()), isinstance(self.topology.mtu, int))))
        Ensures(Acc(spkt.State(), 1/2))
        Ensures(Acc(self.State(), 1/2))
        Exsures(SCMPPathRequired, Acc(spkt.State(), 1/2))
        """
        Main entry point for data packet handling.

        :param spkt: The SCION Packet to process.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_as:
            Whether or not the packet is from the local AS.
        """
        if Unfolding(Acc(spkt.State(), 1/2), len(spkt.path)) == 0:
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

    def _process_data(self, t: Place, spkt: SCIONL4Packet, ingress: bool, drop_on_error: bool) -> Place:
        Requires(Acc(spkt.State(), 1 / 2))
        Requires(Acc(self.State(), 1 / 2))
        Requires(Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self.topology.State(), 1/10), isinstance(self.topology.mtu, int))))
        Requires(Unfolding(Acc(spkt.State(), 1/10), spkt.path is not None and spkt.addrs is not None))
        Requires(Unfolding(Acc(spkt.State(), 1/10), Unfolding(Acc(spkt.addrs.State(), 1/10), spkt.addrs.dst is not None)))
        Requires(Unfolding(Acc(spkt.State(), 1/10), Unfolding(Acc(spkt.path.State(), 1/10), isinstance(spkt.path._iof_idx, int))))
        Requires(Unfolding(Acc(spkt.State(), 1/10), Unfolding(Acc(spkt.path.State(), 1/10), isinstance(spkt.path._hof_idx, int))))
        Ensures(Acc(spkt.State(), 1 / 2))
        Ensures(Acc(self.State(), 1 / 2))
        Exsures(SCIONBaseError, Acc(spkt.State(), 1 / 2))
        Exsures(SCIONBaseError, Acc(self.State(), 1 / 2))
        # Exsures(SCIONBaseError, Unfolding(Rd(spkt.State()), spkt.path != None))
        # Exsures(SCIONBaseError, Unfolding(Rd(spkt.State()), Unfolding(Rd(spkt.path.State()), not valid_hof(spkt.path))))
        path = Unfolding(Acc(spkt.State(), 1/10), spkt.path)
        if len(spkt) > Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self.topology.State(), 1/10), self.topology.mtu)):
            # FIXME(kormat): ignore this check for now, as PCB packets are often
            # over MTU, it's just that udp-overlay handles fragmentation for us.
            # Once we have TCP/SCION, this check should be re-instated.
            # This also needs to look at the specific MTU for the relevant link
            # if on egress.
            #  raise SCMPOversizePkt("Packet larger than mtu", mtu)
            pass
        Unfold(Acc(spkt.State(), 1/4))
        self.verify_hof(path, ingress=ingress)
        hof = spkt.path.get_hof()
        if Unfolding(Acc(spkt.path.State(), 1/10), Unfolding(Acc(spkt.path._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.verify_only))):
            Fold(Acc(spkt.State(), 1/4))
            raise SCMPNonRoutingHOF
        # FIXME(aznair): Remove second condition once PathCombinator is less
        # stupid.
        if (Unfolding(Acc(spkt.addrs.State(), 1/10), Unfolding(Acc(spkt.addrs.dst.State(), 1/10), spkt.addrs.dst.isd_as)) == Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self.addr.State(), 1/10), self.addr.isd_as)) and
                spkt.path.is_on_last_segment()):
            self.deliver(t, spkt)
            Fold(Acc(spkt.State(), 1 / 4))
            return t
        if ingress:
            prev_if = path.get_curr_if()
            prev_iof = path.get_iof()
            prev_hof = path.get_hof()
            prev_iof_idx = path.get_of_idxs()[0]
            fwd_if, path_incd, skipped_vo = self._calc_fwding_ingress(spkt)
            cur_iof_idx = path.get_of_idxs()[0]
            if prev_iof_idx != cur_iof_idx:
                self._validate_segment_switch(
                    path, fwd_if, prev_if, prev_iof, prev_hof)
            elif skipped_vo:
                Fold(Acc(spkt.State(), 1 / 4))
                raise SCIONSegmentSwitchError("Skipped verify only field, but "
                                              "did not switch segments.")
        else:
            assert False
            fwd_if = path.get_fwd_if()
            path_incd = False
        try:
            br = self.ifid2br[fwd_if]
            if_addr, port = br.addr, br.port
        except KeyError:
            # So that the error message will show the current state of the
            # packet.
            assert False
            spkt.update()
            logging.error("Cannot forward packet, fwd_if is invalid (%s):\n%s",
                          fwd_if, spkt)
            raise SCMPBadIF(fwd_if) from None
        if not self.if_states[fwd_if].is_active:
            if drop_on_error:
                logging.debug("IF is down, but drop_on_error is set, dropping")
                return t
            self.send_revocation(spkt, fwd_if, ingress, path_incd)
            Fold(Acc(spkt.State(), 1 / 4))
            return t
        if ingress:
            logging.debug("Sending to IF %s (%s:%s)", fwd_if, if_addr, port)
            Fold(Acc(spkt.State(), 1 / 4))
            return self.send(t, spkt, if_addr, port)
        else:
            path.inc_hof_idx()
            Fold(Acc(spkt.State(), 1 / 4))
            return self._egress_forward(t, spkt)

    def _validate_segment_switch(self, path: SCIONPath, fwd_if: int, prev_if: int,
                                 prev_iof: InfoOpaqueField,
                                 prev_hof: HopOpaqueField) -> None:
        Requires(False)
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
        if not prev_iof.up_flag and cur_iof.up_flag:
            raise SCIONSegmentSwitchError(
                "Switching from down- to up-segment is not allowed.")
        if (prev_iof.up_flag and cur_iof.up_flag and
                    fwd_on_link_type != LinkType.ROUTING):
            raise SCIONSegmentSwitchError(
                "Switching from up- to up-segment is not allowed "
                "if the packet is not forwarded over a ROUTING link.")
        if (not prev_iof.up_flag and not cur_iof.up_flag and
                    rcvd_on_link_type != LinkType.ROUTING):
            raise SCIONSegmentSwitchError(
                "Switching from down- to down-segment is not "
                "allowed if the packet was not received over a ROUTING link.")
        if (rcvd_on_link_type == LinkType.ROUTING and
                    fwd_on_link_type == LinkType.ROUTING):
            raise SCIONSegmentSwitchError(
                "Switching from core- to core-segment is not allowed.")
        if ((rcvd_on_link_type == LinkType.PEER or
                     fwd_on_link_type == LinkType.PEER) and
                    prev_hof.egress_if != cur_hof.egress_if):
            raise SCIONSegmentSwitchError(
                "Egress IF of peering HOF does not match egress IF of current "
                "HOF.")

    def _calc_fwding_ingress(self, spkt: SCIONL4Packet) -> Tuple[int, bool, bool]:
        Requires(Acc(spkt.State(), 1 / 9))
        Requires(Unfolding(Acc(spkt.State(), 1/9), spkt.path is not None and Unfolding(Acc(spkt.path.State(), 1 / 9), isinstance(spkt.path._iof_idx, int))))
        Requires(Unfolding(Acc(spkt.State(), 1/9), spkt.path is not None and Unfolding(Acc(spkt.path.State(), 1 / 9), isinstance(spkt.path._hof_idx, int))))
        Ensures(Acc(spkt.State(), 1 / 9))
        Unfold(Acc(spkt.State(), 1 / 9))
        path = spkt.path
        hof = path.get_hof()
        assert isinstance(hof, HopOpaqueField)
        incd = False
        skipped_vo = False
        if Unfolding(Acc(path.State(), 1/9), Unfolding(Acc(path._ofs.State(), 1/9), Unfolding(Acc(hof.State(), 1/9), hof.xover))):
            skipped_vo = path.inc_hof_idx()
            incd = True
        result = path.get_fwd_if(), incd, skipped_vo
        # Fold(Acc(path.State(), 1 / 9))
        Fold(Acc(spkt.State(), 1 / 9))
        return result

    def _link_type(self, if_id: int) -> Optional[str]:
        """
        Returns the link type of the link corresponding to 'if_id' or None.
        """
        for br in self.topology.get_all_border_routers():
            if br.interface.if_id == if_id:
                return br.interface.link_type
        return None

    def _needs_local_processing(self, pkt: SCIONL4Packet) -> bool:
        Requires(Acc(self.State(), 1/40))
        Requires(Acc(pkt.State(), 1/40))
        Requires(Unfolding(Acc(pkt.State(), 1/40), pkt.addrs is not None))
        return Unfolding(Acc(pkt.State(), 1/40), Unfolding(Acc(pkt.addrs.State(), 1/40), pkt.addrs.dst)) in [
            Unfolding(Acc(self.State(), 1/40), self.addr),
            SCIONAddr.from_values(Unfolding(Acc(self.State(), 1/40), Unfolding(Acc(self.addr.State(), 1/40), self.addr.isd_as)),
                                  Unfolding(Acc(self.State(), 1/40), Unfolding(Acc(self.interface.State(), 1/40), self.interface.addr))),
        ]

    def _process_flags(self, flags: List[Tuple[int, ...]], pkt: SCIONL4Packet, from_local_as: bool) -> Tuple[bool, bool]:
        """
        Go through the flags set by hop-by-hop extensions on this packet.
        :returns:
        """
        Requires(Acc(list_pred(flags), 1/9))
        Requires(len(flags) == 0)
        Ensures(Acc(list_pred(flags), 1/9))
        Ensures(not Result()[1])
        process = False
        # First check if any error or no_process flags are set
        for (flag, *args) in flags:
            Invariant(len(flags) == 0)
            if flag == RouterFlag.ERROR:
                logging.error("%s", args[0])
                return True, False
            elif flag == RouterFlag.NO_PROCESS:
                return True, False
        # Now check for other flags
        for (flag, *args) in flags:
            Invariant(len(flags) == 0)
            Invariant(process == False)
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

        """
        Main routine to handle incoming SCION packets.

        :param bytes packet: The incoming packet to handle.
        :param tuple sender: Tuple of sender IP, port.
        :param bool from_local_socket:
            True, if the packet was received on the local socket.
        """
        from_local_as = from_local_socket
        pkt = self._parse_packet(packet)
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
            assert False
        else:
            # It's a normal packet, just forward it.
            handler = True # self.handle_data
        logging.debug("handle_request (from_local_as? %s):"
                      "\n  %s\n  %s\n  handler: %s",
                      from_local_as, pkt.cmn_hdr, pkt.addrs, handler)
        if not handler:
            return t
        try:
            return self.handle_data(t, pkt, from_local_as)
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)

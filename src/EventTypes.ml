(* All events should have a proper type to make field access faster and detect
 * any typing bug when the configuration is compiled.  Also helps to make
 * events as sophisticated as we need/like.
 *
 * This is rather ugly due to the heavy "ppp" things, which are
 * pretty-printer and parsers. This should come as a compiler plugin and
 * disappear from here at some point.
 *)
open Stdint

(* Time as in the CSV: microseconds since epoch. *)
type time = int [@@ppp PPP_OCaml]
let to_useconds t = t
let to_mseconds t = t / 1_000
let to_seconds t = t / 1_000_000
let to_minutes t = t / 60_000_000
let of_useconds x = x
let of_mseconds x = x * 1_000
let of_seconds x = x * 1_000_000
let of_minutes x = x * 60_000_000

type ip_port = int [@@ppp PPP_OCaml]

(* We put the server first *)
type ip_endpoints = IPv4s of (uint32 * uint32)
                  | IPv6s of (int128 * int128) [@@ppp PPP_OCaml]

type socket = {
  (* client * server *)
  endpoints : ip_endpoints ;
  ports : ip_port * ip_port
} [@@ppp PPP_OCaml]

module TCP_v29 =
struct
  (*$< TCP_v29 *)
  (* This is weird and should go away! *)
  type itf = CltOnly of int
           | SrvOnly of int
           | Same of int
           | Split of int * int [@@ppp PPP_OCaml]

  type zone = int [@@ppp PPP_OCaml]

  type t =
    { mutable start : time ;
      mutable stop : time ;
      itf : itf ;
      zone_clt : zone ;
      zone_srv : zone ;
      socket : socket option ; (* unset for "others" *)
      mutable packets_clt : int ;
      mutable packets_srv : int ;
      mutable max_missed : int ; (* max number of uncounted packets *)
      mutable bytes_clt : int ;
      mutable bytes_srv : int } [@@ppp PPP_OCaml]

  module JunkieCSV =
  struct
    module P = PPP
    include P.Ops

    let max_line_length = 1024

    let string = P.{
      printer = (fun o v -> o v) ;
      scanner = (fun i o ->
        let s = i o max_line_length in
        Some (s, o + String.length s)) ;
      descr = "string" }

    let option ppp = P.option ~placeholder:(cst "<NULL>") ppp

    let dbg = false
    let csv_ppp =
      let printer o _v = o "TODO\n" in
      let scanner i o =
        let line = i o max_line_length in
        (* We trust IO not to make us wait forever in case of EOF
         * (for files) or broken pipe (for fifos).
         * Supposedly, we already have a full message so here we just
         * request the whole of it. *)
        if String.length line >= max_line_length then
          Printf.eprintf "CSV lines longer than max length (%d)!\n%!"
            max_line_length ;
        if dbg then Printf.eprintf "Read a line: %S\n%!" line ;
        (* Get all the separator positions *)
        let column_start_pos = Array.make 78 0 in
        let rec loop n from =
          if n < Array.length column_start_pos then (
            column_start_pos.(n) <- from ;
            let next =
              if from >= String.length line then String.length line + 1 (* the imaginary \n *) else
              match String.index_from line from '\t' with
              | exception Not_found ->
                String.length line + 1 (* the imaginary \n *)
              | x -> x+1 in
            loop (n+1) next
          ) in
        loop 0 0 ;
        let line_reader stop i l =
          if i >= stop then "" else
          let ll = min l (stop - i) in
          String.sub line i ll in
        let value_at idx ppp =
          let start = column_start_pos.(idx)
          and stop = column_start_pos.(idx+1) - 1 in
          if dbg then Printf.eprintf "start = %d, stop = %d\n%!" start stop ;
          match ppp.PPP.scanner (line_reader stop) start with
          | Some (v, pl) ->
            if dbg then Printf.eprintf "Found value at pos %d-%d, field end at %d\n%!" start pl stop ;
            if pl < stop then (
              failwith (Printf.sprintf
                "Cannot parse field %S entirely (got value %s)"
                 (String.sub line start (stop - start))
                (PPP.to_string ppp v))
            ) else (
              assert (pl = stop) ;
              v
            )
          | None ->
            failwith (Printf.sprintf
              "Cannot parse field %S as a %s"
                (String.sub line start (stop - start))
                ppp.PPP.descr)
        in
        try
          (* Note: evaluation order of a product is unspecified :-( *)
          let v =
            value_at 0 string (* poller *) (* 1 *),
            value_at 1 int (* capture_begin *),
            value_at 2 int (* capture_end *),
            value_at 3 (option int) (* device_client *),
            value_at 4 (option int) (* device_server *),
            value_at 5 (option int) (* vlan_client *),
            value_at 6 (option int) (* vlan_server *),
            value_at 7 (option int64) (* mac_client *),
            value_at 8 (option int64) (* mac_server *),
            value_at 9 int (* zone_client *) (* 10 *),
            value_at 10 int (* zone_server *),
            value_at 11 (option uint32) (* ip4_client *),
            value_at 12 (option int128) (* ip6_client *),
            value_at 13 (option uint32) (* ip4_server *),
            value_at 14 (option int128) (* ip6_server *),
            value_at 15 (option uint32) (* ip4_external *),
            value_at 16 (option int128) (* ip6_external *),
            value_at 17 int (* port_client *),
            value_at 18 int (* port_server *),
            value_at 19 int (* diffserv_client - actually never NULL *) (* 20 *),
            value_at 20 int (* diffserv_server - actually never NULL *),
            value_at 21 (option int) (* os_client *),
            value_at 22 (option int) (* os_server *),
            value_at 23 (option int) (* mtu_client *),
            value_at 24 (option int) (* mtu_server *),
            value_at 25 (option string) (* captured_pcap *),
            value_at 26 int (* application - actually never NULL *),
            value_at 27 (option string) (* protostack *),
            value_at 28 (option string) (* uuid - actually can be NULL! *),
            value_at 29 int (* traffic_bytes_client - actually never NULL *) (* 30 *),
            value_at 30 int (* traffic_bytes_server - actually never NULL *),
            value_at 31 int (* traffic_packets_client - actually never NULL *),
            value_at 32 int (* traffic_packets_server - actually never NULL *),
            value_at 33 int (* payload_bytes_client - actually never NULL *),
            value_at 34 int (* payload_bytes_server - actually never NULL *),
            value_at 35 int (* payload_packets_client - actually never NULL *),
            value_at 36 int (* payload_packets_server - actually never NULL *),
            value_at 37 (option int) (* retrans_traffic_bytes_client *),
            value_at 38 (option int) (* retrans_traffic_bytes_server *),
            value_at 39 (option int) (* retrans_payload_bytes_client *) (* 40 *),
            value_at 40 (option int) (* retrans_payload_bytes_server *),
            value_at 41 (option int) (* syn_count_client *),
            value_at 42 (option int) (* fin_count_client *),
            value_at 43 (option int) (* fin_count_server *),
            value_at 44 (option int) (* rst_count_client *),
            value_at 45 (option int) (* rst_count_server *),
            value_at 46 int (* timeout_count - actually never NULL *),
            value_at 47 (option int) (* close_count *),
            value_at 48 (option int) (* dupack_count_client *),
            value_at 49 (option int) (* dupack_count_server *) (* 50 *),
            value_at 50 (option int) (* zero_window_count_client *),
            value_at 51 (option int) (* zero_window_count_server *),
            value_at 52 (option int) (* ct_count *),
            value_at 53 int (* ct_sum - actually never NULL *),
            value_at 54 int (* ct_square_sum - actually never NULL *),
            value_at 55 (option int) (* rt_count_server *),
            value_at 56 int (* rt_sum_server - actually never NULL *),
            value_at 57 int (* rt_square_sum_server - actually never NULL *),
            value_at 58 (option int) (* rtt_count_client *),
            value_at 59 int (* rtt_sum_client - actually never NULL *) (* 60 *),
            value_at 60 int (* rtt_square_sum_client - actually never NULL *),
            value_at 61 (option int) (* rtt_count_server *),
            value_at 62 int (* rtt_sum_server - actually never NULL *),
            value_at 63 int (* rtt_square_sum_server - actually never NULL *),
            value_at 64 (option int) (* rd_count_client *),
            value_at 65 int (* rd_sum_client - actually never NULL *),
            value_at 66 int (* rd_square_sum_client - actually never NULL *),
            value_at 67 (option int) (* rd_count_server *),
            value_at 68 int (* rd_sum_server - actually never NULL *),
            value_at 69 int (* rd_square_sum_server - actually never NULL *) (* 70 *),
            value_at 70 (option int) (* dtt_count_client *),
            value_at 71 int (* dtt_sum_client - actually never NULL *),
            value_at 72 int (* dtt_square_sum_client - actually never NULL *),
            value_at 73 (option int) (* dtt_count_server *),
            value_at 74 int (* dtt_sum_server - actually never NULL *),
            value_at 75 int (* dtt_square_sum_server - actually never NULL *),
            value_at 76 (option string) (* dcerpc_uuid *)
          in
          Some (v, String.length line)
        with Failure x ->
          Printf.eprintf "Parse error: %s\n%!" x ;
          None
      in
      PPP.{ printer ; scanner ; descr = "tcp_v29" }
  end

  type csv =
    string (* poller *) *                                (* 1 *)
    int (* capture_begin *) *
    int (* capture_end *) *
    int option (* device_client *) *
    int option (* device_server *) *
    int option (* vlan_client *) *
    int option (* vlan_server *) *
    int64 option (* mac_client *) *
    int64 option (* mac_server *) *
    int (* zone_client *) *                               (* 10 *)
    int (* zone_server *) *
    uint32 option (* ip4_client *) *
    int128 option (* ip6_client *) *
    uint32 option (* ip4_server *) *
    int128 option (* ip6_server *) *
    uint32 option (* ip4_external *) *
    int128 option (* ip6_external *) *
    int (* port_client *) *
    int (* port_server *) *
    int (* diffserv_client - actually never NULL *) *                    (* 20 *)
    int (* diffserv_server - actually never NULL *) *
    int option (* os_client *) *
    int option (* os_server *) *
    int option (* mtu_client *) *
    int option (* mtu_server *) *
    string option (* captured_pcap *) *
    int (* application - actually never NULL *) *
    string option (* protostack *) *
    string option (* uuid - actually can be NULL! *) *
    int (* traffic_bytes_client - actually never NULL *) *               (* 30 *)
    int (* traffic_bytes_server - actually never NULL *) *
    int (* traffic_packets_client - actually never NULL *) *
    int (* traffic_packets_server - actually never NULL *) *
    int (* payload_bytes_client - actually never NULL *) *
    int (* payload_bytes_server - actually never NULL *) *
    int (* payload_packets_client - actually never NULL *) *
    int (* payload_packets_server - actually never NULL *) *
    int option (* retrans_traffic_bytes_client *) *
    int option (* retrans_traffic_bytes_server *) *
    int option (* retrans_payload_bytes_client *) *       (* 40 *)
    int option (* retrans_payload_bytes_server *) *
    int option (* syn_count_client *) *
    int option (* fin_count_client *) *
    int option (* fin_count_server *) *
    int option (* rst_count_client *) *
    int option (* rst_count_server *) *
    int (* timeout_count - actually never NULL *) *
    int option (* close_count *) *
    int option (* dupack_count_client *) *
    int option (* dupack_count_server *) *                (* 50 *)
    int option (* zero_window_count_client *) *
    int option (* zero_window_count_server *) *
    int option (* ct_count *) *
    int (* ct_sum - actually never NULL *) *
    int (* ct_square_sum - actually never NULL *) *
    int option (* rt_count_server *) *
    int (* rt_sum_server - actually never NULL *) *
    int (* rt_square_sum_server - actually never NULL *) *
    int option (* rtt_count_client *) *
    int (* rtt_sum_client - actually never NULL *) *                     (* 60 *)
    int (* rtt_square_sum_client - actually never NULL *) *
    int option (* rtt_count_server *) *
    int (* rtt_sum_server - actually never NULL *) *
    int (* rtt_square_sum_server - actually never NULL *) *
    int option (* rd_count_client *) *
    int (* rd_sum_client - actually never NULL *) *
    int (* rd_square_sum_client - actually never NULL *) *
    int option (* rd_count_server *) *
    int (* rd_sum_server - actually never NULL *) *
    int (* rd_square_sum_server - actually never NULL *) *               (* 70 *)
    int option (* dtt_count_client *) *
    int (* dtt_sum_client - actually never NULL *) *
    int (* dtt_square_sum_client - actually never NULL *) *
    int option (* dtt_count_server *) *
    int (* dtt_sum_server - actually never NULL *) *
    int (* dtt_square_sum_server - actually never NULL *) *
    string option (* dcerpc_uuid *) (*[@@ppp JunkieCSV]*)

  (* Convert a CSV value into our nicer structure: *)
  let of_csv (
      _poller, start, stop, device_clt, device_srv, _vlan_clt, _vlan_srv,
      _mac_clt, _mac_srv, zone_clt, zone_srv, ip4_clt, ip6_clt,
      ip4_srv, ip6_srv, _ip4_external, _ip6_external, port_clt, port_srv,
      _diffserv_clt, _diffserv_srv, _os_clt, _os_srv, _mtu_clt, _mtu_srv,
      _captured_pcap, _application, _protostack, _uuid,
      bytes_clt, bytes_srv, packets_clt, packets_srv,
      _payload_bytes_clt, _payload_bytes_srv, _payload_packets_clt, _payload_packets_srv,
      _retrans_bytes_clt, _retrans_bytes_srv,
      _retrans_payload_bytes_clt, _retrans_payload_bytes_srv,
      _syn_count_clt, _fin_count_clt, _fin_count_srv, _rst_count_clt,
      _rst_count_srv, _timeout_count, _close_count,
      _dupack_count_clt, _dupack_count_srv,
      _zero_window_count_clt, _zero_window_count_srv,
      _ct_count, _ct_sum, _ct_square_sum, _rt_count_srv,
      _rt_sum_srv, _rt_square_sum_srv,
      _rtt_count_clt, _rtt_sum_clt, _rtt_square_sum_clt,
      _rtt_count_srv, _rtt_sum_srv, _rtt_square_sum_srv,
      _rd_count_clt, _rd_sum_clt, _rd_square_sum_clt,
      _rd_count_srv, _rd_sum_srv, _rd_square_sum_srv,
      _dtt_count_clt, _dtt_sum_clt, _dtt_square_sum_clt,
      _dtt_count_srv, _dtt_sum_srv, _dtt_square_sum_srv,
      _dcerpc_uuid) =
    let itf =
      match device_clt, device_srv with
      | Some i, None -> CltOnly i
      | None, Some i -> SrvOnly i
      | Some i, Some j -> if i = j then Same i else Split (i, j)
      | None, None -> invalid_arg "device" in
    let endpoints =
      match ip4_clt, ip6_clt, ip4_srv, ip6_srv with
      | Some c4, None, Some s4, None -> IPv4s (c4, s4)
      | None, Some c4, None, Some s4 -> IPv6s (c4, s4)
      | _ -> invalid_arg "IPs" in
    { start ; stop ; itf ;
      zone_clt ; zone_srv ;
      socket = Some { endpoints ; ports = port_clt, port_srv } ;
      packets_clt ; packets_srv ; max_missed = 0 ;
      bytes_clt ; bytes_srv }

  let to_csv _ = failwith "No reason to do that"

  let of_csv_ppp = PPP.(JunkieCSV.csv_ppp >>: (to_csv, of_csv))
  (*$< Stdint *)
  (*$= of_csv_ppp & ~printer:(function None -> "None" | Some (e, o) -> Printf.sprintf "Some %s, len %d" (PPP.to_string t_ppp e) o)
    (Some ({ start = 1493409124690894 ; stop = 1493409128296658 ; itf = Split (3,4) ; \
             zone_clt = 404 ; zone_srv = 0 ; \
             socket = Some { endpoints = IPv4s (Uint32.of_int 3241271562, Uint32.of_int 2007484923) ; ports= 41383, 1104 }; \
             packets_clt = 5 ; packets_srv = 5 ; bytes_clt = 904 ; bytes_srv = 655 ; \
             max_missed = 0 }, 394)) \
      (PPP.of_string of_csv_ppp "9GJ3152\t1493409124690894\t1493409128296658\t3\t4\t250\t250\t149825120988417\t198620281134081\t404\t0\t3241271562\t<NULL>\t2007484923\t<NULL>\t<NULL>\t<NULL>\t41383\t1104\t0\t0\t14\t0\t618\t369\t<NULL>\t211\tEthernet/IPv4/TCP/HTTP\t1b2c5dda-ae39-47b0-8ec6-962e784cd0f2\t904\t655\t5\t5\t566\t317\t3\t3\t0\t0\t0\t0\t1\t1\t1\t0\t0\t0\t1\t0\t0\t0\t0\t1\t91248\t8326197504\t1\t66129\t4373044641\t2\t82\t3380\t3\t219698\t16580405684\t0\t0\t0\t0\t0\t0\t1\t0\t0\t1\t0\t0\t<NULL>" 0)
    (Some ({ start = 1493409169958547 ; stop = 1493409171229361 ; itf = CltOnly 7 ; \
             zone_clt = 0 ; zone_srv = 0 ; \
             socket = Some { endpoints = IPv6s (Int128.of_string "-127591584635405263362148620169206776797", \
                                                Int128.of_string "-127600695269105035184451414759617478119") ; \
                             ports = 63012, 62848 } ; \
             packets_clt = 6 ; packets_srv = 0 ; max_missed = 0 ; bytes_clt = 700 ; bytes_srv = 0 }, 440)) \
      (PPP.of_string of_csv_ppp "9GJ3152\t1493409169958547\t1493409171229361\t7\t<NULL>\t250\t<NULL>\t198620281134081\t149825120988417\t0\t0\t<NULL>\t-127591584635405263362148620169206776797\t<NULL>\t-127600695269105035184451414759617478119\t<NULL>\t<NULL>\t63012\t62848\t0\t0\t0\t0\t116\t0\t<NULL>\t0\tEthernet/IPv4/GRE/IPv4/IPv6/TCP\td85a0b79-01db-4bd8-bd6e-b6de1f34027a\t700\t0\t6\t0\t0\t0\t6\t0\t386\t0\t0\t0\t6\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t3\t162517895\t26001502904081625\t0\t0\t0\t0\t0\t0\t0\t0\t0\t<NULL>" 0)
    (Some ({ start = 1493409175525589 ; stop = 1493409205920697 ; itf = Same 4 ; \
             zone_clt = 8 ; zone_srv = 3 ; \
             socket = Some { endpoints = IPv4s (Uint32.of_int 3232238239, Uint32.of_int 3232256022) ; ports= 49767, 445 }; \
             packets_clt = 4 ; packets_srv = 2 ; bytes_clt = 334 ; bytes_srv = 214 ; \
             max_missed = 0 }, 401)) \
      (PPP.of_string of_csv_ppp "9GJ3152\t1493409175525589\t1493409205920697\t4\t4\t<NULL>\t<NULL>\t116350668307\t190070690676994\t8\t3\t3232238239\t<NULL>\t3232256022\t<NULL>\t<NULL>\t<NULL>\t49767\t445\t0\t0\t0\t0\t93\t93\t<NULL>\t47\tEthernet/IPv4/TCP/Netbios/SMB\te36285e8-68c5-4128-9288-cb958ad9a1e9\t334\t214\t4\t2\t106\t106\t2\t2\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t2\t287\t42109\t2\t81379\t3311416081\t0\t0\t0\t0\t0\t0\t0\t0\t0\t2\t0\t0\t2\t0\t0\t4b324fc8-1670-01d3-1278-5a47bf6ee188" 0)
   *)
   (*$>*)
   (*$>*)
end

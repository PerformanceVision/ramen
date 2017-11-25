(* Collector for netflow v5.  *)
open Batteries
open RamenLog
open Lwt
open Helpers
open Stdint

(* <blink>DO NOT ALTER</blink> this record without also updating
 * wrap_netflow_decode in wrap_netflow.c and tuple_typ below! *)
type netflow_metric =
  string * float * float *
  Uint32.t * Uint8.t * Uint8.t * Uint8.t * Uint16.t *
  Uint32.t * Uint32.t * Uint32.t * Uint16.t * Uint16.t *
  Uint16.t * Uint16.t * Uint32.t * Uint32.t * Uint8.t * Uint8.t *
  Uint8.t * Uint16.t * Uint16.t * Uint8.t * Uint8.t
  
let tuple_typ =
  let open RamenSharedTypes in
  [ { typ_name = "source" ; nullable = false ; typ = TString } ;
    { typ_name = "first" ; nullable = false ; typ = TFloat } ;
    { typ_name = "last" ; nullable = false ; typ = TFloat } ;
    { typ_name = "seqnum" ; nullable = false ; typ = TU32 } ;
    { typ_name = "engine_type" ; nullable = false ; typ = TU8 } ;
    { typ_name = "engine_id" ; nullable = false ; typ = TU8 } ;
    { typ_name = "sampling_type" ; nullable = false ; typ = TU8 } ;
    { typ_name = "sampling_rate" ; nullable = false ; typ = TU16 } ;
    { typ_name = "src" ; nullable = false ; typ = TIpv4 } ;
    { typ_name = "dst" ; nullable = false ; typ = TIpv4 } ;
    { typ_name = "next_hop" ; nullable = false ; typ = TIpv4 } ;
    { typ_name = "src_port" ; nullable = false ; typ = TU16 } ;
    { typ_name = "dst_port" ; nullable = false ; typ = TU16 } ;
    { typ_name = "in_iface" ; nullable = false ; typ = TU16 } ;
    { typ_name = "out_iface" ; nullable = false ; typ = TU16 } ;
    { typ_name = "packets" ; nullable = false ; typ = TU32 } ;
    { typ_name = "bytes" ; nullable = false ; typ = TU32 } ;
    { typ_name = "tcp_flags" ; nullable = false ; typ = TU8 } ;
    { typ_name = "ip_proto" ; nullable = false ; typ = TU8 } ;
    { typ_name = "ip_tos" ; nullable = false ; typ = TU8 } ;
    { typ_name = "src_as" ; nullable = false ; typ = TU16 } ;
    { typ_name = "dst_as" ; nullable = false ; typ = TU16 } ;
    { typ_name = "src_mask" ; nullable = false ; typ = TU8 } ;
    { typ_name = "dst_mask" ; nullable = false ; typ = TU8 } ]

external decode :
  Bytes.t -> int -> string -> netflow_metric array =
  "wrap_netflow_v5_decode"

let collector ~inet_addr ~port k =
  (* Listen to incoming UDP datagrams on given port: *)
  let serve sender buffer recv_len =
    !logger.debug "Received %d bytes from netflow source @ %s"
      recv_len sender ;
    decode buffer recv_len sender |>
    Array.fold_left (fun th tuple -> th >>= fun () -> k tuple) return_unit
  in
  udp_server ~inet_addr ~port serve

let test ?(port=2055) () =
  logger := make_logger true ;
  let display_tuple _t =
    return_unit in
  Lwt_main.run (collector ~inet_addr:Unix.inet_addr_any ~port display_tuple)

(* Global configuration for rigatoni daemon *)
open Batteries

type node =
  { operation : Lang.Operation.t ;
    mutable parents : node list ;
    mutable children : node list }

type graph =
  { nodes : (string, node) Hashtbl.t }

type conf =
  { logger : Log.logger ;
    running_graph : graph ;
    save_file : string }

let make_node _conf operation =
  { operation ; parents = [] ; children = [] }

let make_new_graph () =
  { nodes = Hashtbl.create 17 }

let make_graph logger save_file =
  try
    File.with_file_in save_file (fun ic -> Marshal.input ic)
  with
    | Sys_error err ->
      logger.Log.debug "Cannot read state from file %S: %s. Starting anew" save_file err ;
      make_new_graph ()
    | BatInnerIO.No_more_input ->
      logger.Log.debug "Cannot read state from file %S: not enough input. Starting anew" save_file ;
      make_new_graph ()

let save_graph conf graph =
  conf.logger.Log.debug "Saving graph in %S\n%!" conf.save_file ;
  File.with_file_out ~mode:[`create; `trunc] conf.save_file (fun oc ->
    Marshal.output oc graph)

let has_node _conf graph id =
  Hashtbl.mem graph.nodes id

let find_node _conf graph id =
  Hashtbl.find graph.nodes id

let add_node conf graph id node =
  Hashtbl.add graph.nodes id node ;
  save_graph conf graph

let remove_node conf graph id =
  let node = Hashtbl.find graph.nodes id in
  List.iter (fun p ->
      p.children <- List.filter ((!=) node) p.children
    ) node.parents ;
  List.iter (fun p ->
      p.parents <- List.filter ((!=) node) p.parents
    ) node.children ;
  Hashtbl.remove_all graph.nodes id ;
  save_graph conf graph

let make_conf debug save_file =
  let logger = Log.make_logger debug in
  { logger ; running_graph = make_graph logger save_file ; save_file }
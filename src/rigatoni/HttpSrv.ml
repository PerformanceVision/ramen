(* Start an HTTP(S) daemon to allow setting up the configuration graph. *)
open Batteries
open BatOption.Infix
open Cohttp
open Cohttp_lwt_unix
open Lwt
open RamenConf

(* API:

== Add/Delete a node ==

Nodes are referred to via name that can be anything as long as they are unique.
So the client decide on the name. The server ensure uniqueness by forbidding
creation of a new node by the same name as one that exists already.

So each node has a URL, such as: node/$name
We can then PUT, GET or DELETE that URL.

For RPC like messages, the server accept all encodings supported by PPP. But we
have to find a way to generate several ppp for a type, under different names.
Or even better, we should have a single value (t_ppp) with all the encodings
(so that we can pass around the ppp for all encodings). So the @@ppp notation
would just create a record with one field per implemented format. Later, if
some are expensive, we could have an option to list only those wanted ; the
default being to include them all. For now we will use only JSON.

Here is the node description. Typically, optional fields are optional or even
forbidden when creating the node and are set when getting node information.

*)

exception HttpError of (int * string)

let not_implemented msg = fail (HttpError (501, msg))
let bad_request msg = fail (HttpError (400, msg))

let json_content_type = "application/json"

let get_content_type headers =
  Header.get headers "Content-Type" |? json_content_type |> String.lowercase

(* PUT *)

type make_node =
  { (* The input type of this node is any tuple source with at least all the
     * field mentioned in the "in" tuple of its operation. *)
    operation : string ; (* description of what this node does in the DSL defined in Lang.ml *)
    (* Fine tunning info about the size of in/out ring buffers etc. *)
    input_ring_size : int option [@ppp_default None] ;
    output_ring_size : int option [@ppp_default None] } [@@ppp PPP_JSON]

(*$= make_node_ppp & ~printer:(PPP.to_string make_node_ppp)
  { operation = "test" ;\
    input_ring_size = None ;\
    output_ring_size = None ;\
    info = None }\
    (PPP.of_string_exc make_node_ppp "{\"operation\":\"test\"}")

  { operation = "op" ;\
    input_ring_size = Some 42 ;\
    output_ring_size = None ;\
    info = None }\
    (PPP.of_string_exc make_node_ppp "{\"operation\":\"op\", \"input_ring_size\":42}")
*)

let put_node conf name msg =
  if has_node conf conf.running_graph name then
    bad_request ("Node "^name^" already exists") else
  let open Lang.P in
  let p = Lang.Operation.Parser.p +- Lang.opt_blanks +- eof in
  (* TODO: enable error correction *)
  match p [] None Parsers.no_error_correction (stream_of_string msg.operation) |>
        to_result with
  | Bad e ->
    let err = IO.to_string (Lang.P.print_bad_result Lang.Operation.print) e in
    bad_request ("Parse error: "^ err)
  | Ok (op, _) -> (* Since we force EOF, no need to keep what's left to parse *)
    let node = make_node conf op in
    add_node conf conf.running_graph name node ;
    let status = `Code 200 in
    Server.respond_string ~status ~body:"" ()

let put conf path headers body =
  (* Get the message from the body *)
  if get_content_type headers <> json_content_type then
    bad_request "Bad content type"
  else match PPP.of_string_exc make_node_ppp body with
  | exception e -> fail e
  | msg ->
    let paths =
      String.nsplit path "/" |>
      List.filter (fun s -> String.length s > 0) in
    match paths with
    | ["node" ; name] ->
      put_node conf name msg
    | _ ->
      fail (HttpError (404, "No such resource"))

(* GET *)

type node_id = string [@@ppp PPP_JSON]

type node_info =
  (* I'd like to offer the AST but PPP still fails on recursive types :-( *)
  { operation : string } [@@ppp PPP_JSON]

let get_node conf name =
  match find_node conf conf.running_graph name with
  | exception Not_found ->
    fail (HttpError (404, "No such node"))
  | node ->
    let node_info =
      { operation = IO.to_string Lang.Operation.print node.operation } in
    let body = PPP.to_string node_info_ppp node_info ^"\n" in
    let status = `Code 200 in
    Server.respond_string ~status ~body ()

let get conf path _headers =
  let paths =
    String.nsplit path "/" |>
    List.filter (fun s -> String.length s > 0) in
  match paths with
  | ["node" ; name] ->
    get_node conf name
  | _ ->
    fail (HttpError (404, "No such resource"))

(* DELETE *)

let del_node conf name =
  match remove_node conf conf.running_graph name with
  | exception Not_found ->
    fail (HttpError (404, "No such node"))
  | () ->
    let status = `Code 200 in
    Server.respond_string ~status ~body:"" ()

let del conf path _headers =
  let paths =
    String.nsplit path "/" |>
    List.filter (fun s -> String.length s > 0) in
  match paths with
  | ["node" ; name] ->
    del_node conf name
  | _ ->
    fail (HttpError (404, "No such resource"))

(*
== Connect nodes ==

== Get info about a node ==

== Display the graph (json or svg representation) ==

*)

(* The function called for each HTTP request: *)

let callback conf _conn req body =
  (* What is this about? *)
  let uri = Request.uri req in
  let path = Uri.path uri
  and headers = Request.headers req in
  let%lwt body_str = Cohttp_lwt_body.to_string body
  in
  catch
    (fun () ->
      try
        match Request.meth req with
        | `PUT -> put conf path headers body_str
        | `GET -> get conf path headers
        | `DELETE -> del conf path headers
        | _ -> fail (HttpError (405, "Method not implemented"))
      with exn -> fail exn)
    (function
      | HttpError (code, body) ->
        let body = body ^ "\n" in
        let status = Code.status_of_code code in
        Server.respond_error ~status ~body ()
      | exn ->
        let body = Printexc.to_string exn ^ "\n" in
        Server.respond_error ~body ())

(* This will be called as a separate Lwt thread: *)
let start conf port cert_opt key_opt =
  let entry_point = Server.make ~callback:(callback conf) () in
  let tcp_mode = `TCP (`Port port) in
  let t1 =
    let%lwt () = return (conf.logger.Log.info "Starting http server on port %d" port) in
    Server.create ~mode:tcp_mode entry_point in
  let t2 =
    match cert_opt, key_opt with
    | Some cert, Some key ->
      let port = port + 1 in
      let ssl_mode = `TLS (`Crt_file_path cert, `Key_file_path key, `No_password, `Port port) in
      let%lwt () = return (conf.logger.Log.info "Starting https server on port %d" port) in
      Server.create ~mode:ssl_mode entry_point
    | None, None ->
      return (conf.logger.Log.info "Not starting https server")
    | _ ->
      return (conf.logger.Log.info "Missing some of SSL configuration") in
  join [ t1 ; t2 ]
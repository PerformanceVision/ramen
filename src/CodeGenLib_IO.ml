(* Tools for LWT IOs *)
open Lwt
open RamenLog
open Stdint
open Batteries

let tuple_count = ref Uint64.zero
let now = ref 0.

let on_each_input_pre () =
  now := Unix.gettimeofday ();
  tuple_count := Uint64.succ !tuple_count

let read_file_lines ?(do_unlink=false) filename preprocessor k =
  let open_file =
    if preprocessor = "" then (
      fun () ->
        let%lwt fd = Lwt_unix.(openfile filename [ O_RDONLY ] 0x644) in
        return Lwt_io.(of_fd ~mode:Input fd)
    ) else (
      fun () ->
        let f = Helpers.shell_quote filename in
        let s =
          if String.exists preprocessor "%s" then
            String.nreplace preprocessor "%s" f
          else
            preprocessor ^" "^ f
        in
        let cmd = Lwt_process.shell s in
        return (Lwt_process.open_process_in cmd)#stdout
    ) in
  match%lwt open_file () with
  | exception e ->
    !logger.error "Cannot open file %S%s: %s, skipping."
      filename
      (if preprocessor = "" then ""
       else (Printf.sprintf " through %S" preprocessor))
      (Printexc.to_string e) ;
    return_unit
  | chan ->
    !logger.debug "Start reading %S" filename ;
    let%lwt () =
      (* If we used a preprocessor we must wait for EOF before
       * unlinking the file. *)
      if do_unlink && preprocessor = "" then
        Lwt_unix.unlink filename else return_unit in
    let rec read_next_line () =
      match%lwt Lwt_io.read_line chan with
      | exception End_of_file ->
        let%lwt () = Lwt_io.close chan in
        if do_unlink && preprocessor <> "" then
          Lwt_unix.unlink filename else return_unit
      | line ->
        on_each_input_pre () ;
        let%lwt () = k line in
        read_next_line ()
    in
    read_next_line ()

let check_file_exist kind kind_name path =
  !logger.debug "Checking %S is a %s..." path kind_name ;
  let open Lwt_unix in
  let%lwt stats = stat path in
  if stats.st_kind <> kind then
    fail_with (Printf.sprintf "Path %S is not a %s" path kind_name)
  else return_unit

let check_dir_exist = check_file_exist Lwt_unix.S_DIR "directory"

let read_glob_lines ?do_unlink path preprocessor k =
  let dirname = Filename.dirname path
  and glob = Filename.basename path in
  let glob = Globs.compile glob in
  let import_file_if_match filename =
    if Globs.matches glob filename then
      catch
        (fun () ->
          read_file_lines ?do_unlink (dirname ^"/"^ filename) preprocessor k)
        (fun exn ->
          !logger.error "Exception while reading file %s: %s\n%s"
            filename
            (Printexc.to_string exn)
            (Printexc.get_backtrace ()) ;
          return_unit)
    else (
      !logger.debug "File %S is not interesting." filename ;
      return_unit
    ) in
  let%lwt () = check_dir_exist dirname in
  let%lwt handler = RamenFileNotify.make dirname in
  !logger.debug "Import all files in dir %S..." dirname ;
  RamenFileNotify.for_each (fun filename ->
    !logger.debug "New file %S in dir %S!" filename dirname ;
    import_file_if_match filename) handler

let http_notify url =
  (* TODO: time this and add a stat *)
  !logger.debug "Send HTTP notification to %S" url ;
  let open Cohttp in
  let open Cohttp_lwt_unix in
  let headers = Header.init_with "Connection" "close" in
  let%lwt resp, body = Client.get ~headers (Uri.of_string url) in
  let code = resp |> Response.status |> Code.code_of_status in
  if code <> 200 then (
    let%lwt body = Cohttp_lwt.Body.to_string body in
    !logger.error "Received code %d from %S (%S)" code url body ;
    return_unit
  ) else
    Cohttp_lwt.Body.drain_body body

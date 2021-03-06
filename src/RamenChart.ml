open RamenHtml

(** {1 Plot Chart}

  Take functions as much as possible as parameters instead of
  some given choice amongst possible data structures.

  The whole style is supposed to be in the CSS.

*)

let identity x = x
let (|?) a b =
  match a with Some x -> x | None -> b

(** Draw an axis-arrow with graduations, ticks and label. *)
let axis ?(extend_ticks=0.) ?(stroke="#000") ?(stroke_width=1.)
         ?(arrow_size=0.) ?(tick_spacing=100.) ?(tick_length=5.)
         ?(label="") ?(font_size=16.) ?opacity ?base
         ?(string_of_v=short_string_of_float) ?(invert=false)
         (x1, y1) (x2, y2) v_min v_max =
  let sq x = x *. x in
  let axis_len = sqrt (sq (x2-.x1) +. sq (y2-.y1)) in
  (* u, v are unit vectors along axis and perpendicular to it *)
  let ux, uy = (x2 -. x1) /. axis_len, (y2 -. y1) /. axis_len in
  let vx, vy = ~-.uy, ux in
  let mostly_horiz = abs_float ux >= abs_float uy in
  let mostly_horiz = (if invert then not else identity) mostly_horiz in
  let add (ax, ay) (bx, by) = ax +. bx, ay +. by in
  let goto x y = x *. ux +. y *. vx, x *. uy +. y *. vy in
  g [] (
    (path ~stroke ~stroke_width ~fill:"none" ?stroke_opacity:opacity
      (moveto (x1, y1) ^
      lineto (x2, y2) ^
      lineto (add (x2, y2) (goto ~-.arrow_size ~-.arrow_size)) ^
      moveto (x2, y2) ^
      lineto (add (x2, y2) (goto ~-.arrow_size arrow_size)))) ::
    (let x, y =
      add (x2, y2) (goto (-1.5 *. font_size) (if mostly_horiz then (-1.5 *. font_size) else (1.5 *. font_size))) in
    (* TODO: rotate this text *)
    let style =
      if mostly_horiz then "text-anchor:end; dominant-baseline:alphabetic"
                      else "text-anchor:start; dominant-baseline:central" in
    svgtext ~font_size:(1.2 *. font_size) ?stroke_opacity:opacity ?fill_opacity:opacity ~x ~y ~style label) ::
    (
      grid ?base (axis_len /. tick_spacing |> int_of_float) v_min v_max |>
      List.map (fun v ->
        let t = ((v -. v_min) /. (v_max -. v_min)) *. axis_len in
        let tick_start = add (x1, y1) (goto t ~-.tick_length) in
        let tick_stop  = add (x1, y1) (goto t tick_length) in
        g []
          [ line ?stroke_opacity:opacity ~stroke ~stroke_width tick_start tick_stop ;
            line ~stroke ~stroke_width:(stroke_width *. 0.6) ~stroke_opacity:0.1
                 tick_stop (add tick_stop (goto 0. extend_ticks)) ;
            let x, y =
              if mostly_horiz then
                add tick_stop (goto 0. font_size)
              else
                add tick_start (goto 0. ~-.font_size)
              in
            let style =
              if mostly_horiz then "text-anchor:middle; dominant-baseline:hanging"
                              else "text-anchor:end; dominant-baseline:central" in
            g [] (
              string_of_v v |>
              String.split_on_char '\n' |>
              List.map (fun s -> s, font_size) |>
              svgtexts ?stroke_opacity:opacity ?fill_opacity:opacity ~style x y)
          ])))

(** if x_min corresponds to v_min and x_max to v_max, find the x which
 * corresponds to v *)
let get_ratio x_min x_max v_min v_max v =
  let r = (v -. v_min) /. (v_max -. v_min) in
  x_min +. r *. (x_max -. x_min)

(** Draws a grid ready for any XY chart *)
let xy_grid ?(show_vgrid=true) ?stroke ?stroke_width ?font_size
            ?arrow_size ?x_tick_spacing ?y_tick_spacing ?tick_length
            ?x_label ?y_label ?string_of_y ?y2 ?string_of_x
            ?x_base ?y1_base ?y2_base
            (x_min, x_max) (y_min, y_max) (vx_min, vx_max) (vy_min, vy_max) =
  let get_x = get_ratio x_min x_max vx_min vx_max
  and get_y = get_ratio y_min y_max vy_min vy_max in
  let bound_by mi ma v =
    if v < mi then mi else
    if v > ma then ma else
    v in
  let x_orig = bound_by x_min x_max (get_x 0.)
  and y_orig = bound_by y_max y_min (get_y 0.) in (* note that y_min, the Y of the origin, is actually greater the y_max, due to the fact that SVG Y starts at top of img *)
  RamenFormats.reset_all_states () ;
  let x_axis =
    axis ?base:x_base ?stroke ?stroke_width ?arrow_size ?tick_spacing:x_tick_spacing ?font_size ?tick_length
         ?label:x_label ?string_of_v:string_of_x (x_min, y_orig) (x_max, y_orig) vx_min vx_max in
  RamenFormats.reset_all_states () ;
  let y_axis =
    axis ?base:y1_base ?stroke ?stroke_width ?arrow_size ?tick_spacing:y_tick_spacing ?font_size ?tick_length
         ~extend_ticks:(if show_vgrid then x_max -. x_min else 0.)
         ?label:y_label ?string_of_v:string_of_y (x_orig, y_min) (x_orig, y_max) vy_min vy_max in
  RamenFormats.reset_all_states () ;
  let y2_axis = match y2 with
    | None -> g [] []
    | Some (label, string_of_v, vy2_min, vy2_max) ->
      axis ?base:y2_base ?stroke ?stroke_width ?arrow_size ?tick_spacing:y_tick_spacing ?font_size
           ?tick_length ~invert:true ~label ~string_of_v ~opacity:0.5
           (x_max, y_min) (x_max, y_max) vy2_min vy2_max in
  g [] [ x_axis ; y_axis ; y2_axis ]


(** Draws a XY plot.

  Apart from the various parameters to customize the look of the plot,
  the interesting parameter is the fold function.
  It calls back with: the previous folded value, the label of the dataset,
  a boolean telling if the dataset is meant for the primary (true) or
  secondary (false) axis, and a getter (index -> vy).

  Notice the fold_t array trick to force polymorphism of fold.
*)

type label = string
let string_of_label l = l

type pen = {
  color : string ;
  opacity : float ;
  stroke_width : float ;
  filled : bool ;
  fill_opacity : float ;
  dasharray : string option ;
  draw_line : bool ;
  draw_points : bool ;
  label : string ;
}

type stacked = NotStacked | Stacked | StackedCentered
type legend_location =
    NoShow | UpperLeft | UpperRight | BottomLeft | BottomRight
  | Absolute of float * float

type fold_t = {
    (* The bool in there is true for all plots in the "primary" chart, and
     * false once at most for the "secondary" plot. Note: the secondary plot
     * is displayed with a distinct Y axis. *)
    fold : 'a. ('a -> pen -> bool -> (int -> float) -> 'a) -> 'a -> 'a }
type ('h, 'v) shash_t = {
    create : unit -> 'h ;
    find : 'h -> string -> 'v option ;
    add : 'h -> string -> 'v -> unit }
            (* I wonder what's the world record in argument list length? *)
let xy_plot ?(attrs=[]) ?(string_of_y=short_string_of_float)
            ?(string_of_y2=short_string_of_float)
            ?string_of_x
            ?(svg_width=800.) ?(svg_height=600.)
            ?(axis_font_size=14.)
            ?(draw_legend=UpperLeft) ?(legend_font_size=12.)
            ?(margin_bottom=30.) ?(margin_left=10.) ?(margin_top=30.) ?(margin_right=10.)
            ?(y_tick_spacing=70.) ?(x_tick_spacing=180.) ?(tick_length=5.5)
            ?(axis_arrow_h=11.) ?x_base ?y1_base ?y2_base
            ?(stacked_y1=NotStacked) ?(stacked_y2=NotStacked)
            ?(force_show_0=false) ?(show_rate=false) ?x_label_for_rate
            ?(scale_vx=1.)
            x_label y_label
            vx_min_unscaled vx_max_unscaled nb_vx
            shash fold =
  let vx_step_unscaled =
    if nb_vx < 2 then 0.
    else (vx_max_unscaled -. vx_min_unscaled) /.
         (float_of_int (nb_vx - 1)) in
  let vx_min = vx_min_unscaled *. scale_vx
  and vx_step = vx_step_unscaled *. scale_vx in
  let force_show_0 = if stacked_y1 = StackedCentered || stacked_y2 = StackedCentered then true else force_show_0 in
  let stacked = [| stacked_y1 ; stacked_y2 |] in
  let y_label_grid =
    if show_rate && y_label <> "" then y_label ^"/"^ (x_label_for_rate |? x_label) else y_label in
  (* build iter and map from fold *)
  let iter_datasets f = fold.fold (fun _prev pen prim get -> f pen prim get) ()
  and map_datasets f = List.rev @@ fold.fold (fun prev pen prim get -> (f pen prim get) :: prev) []
  and rate_of_vy vy = if show_rate then vy /. vx_step else vy in
  (* Data bounds *)
  let vx_of_bucket i = vx_min +. (float_of_int i +. 0.5) *. vx_step in
  (* TODO: if vx_min is close to 0 (compared to vx_max) then clamp it to 0 *)
  let vx_max = vx_of_bucket (nb_vx-1) in
  (* Compute min/max Y for a given bucket (for primary and secondary Ys) *)
  let label2 = ref None in
  let max_vy = Array.init 2 (fun pi ->
    Array.make nb_vx (if stacked.(pi) = NotStacked then ~-.max_float else 0.))
  and min_vy = Array.init 2 (fun pi ->
    Array.make nb_vx (if stacked.(pi) = NotStacked then max_float else 0.)) in
  let set_min_max pi =
    if stacked.(pi) = NotStacked then
      (* keep the max of the Ys *)
      (fun i c ->
        max_vy.(pi).(i) <- max max_vy.(pi).(i) c ;
        min_vy.(pi).(i) <- min min_vy.(pi).(i) c)
    else
      (* sum the Ys *)
      (fun i c ->
        max_vy.(pi).(i) <- max_vy.(pi).(i) +. c ;
        min_vy.(pi).(i) <- min_vy.(pi).(i) +. c) in
  iter_datasets (fun pen prim get ->
    if not prim then label2 := Some pen.label ;
    let pi = if prim then 0 else 1 in
    for i = 0 to nb_vx-1 do
      let c = get i |> rate_of_vy in
      set_min_max pi i c
    done) ;
  (* Graph geometry in pixels *)
  let max_label_length = y_tick_spacing *. 0.9 in
  let y_axis_x = margin_left +. max_label_length in
  let y2_axis_x = svg_width -. margin_right -. (if !label2 = None then 0. else max_label_length) in
  let x_axis_y = svg_height -. margin_bottom -. axis_font_size *. 1.2 in
  let y_axis_ymin = x_axis_y and y_axis_ymax = margin_top
  and x_axis_xmin = y_axis_x and x_axis_xmax = y2_axis_x in
  (* TODO: if vy_min is close to 0 (compared to vy_max) then clamp it to 0 *)
  let vy_min = Array.make 2 max_float
  and vy_max = Array.make 2 ~-.max_float in
  for pi = 0 to 1 do
    let ma =
      Array.fold_left (fun ma y -> max ma y)
        ~-.max_float max_vy.(pi)
    and mi =
      Array.fold_left (fun mi y -> min mi y)
        max_float min_vy.(pi) in
    vy_max.(pi) <- if force_show_0 then max ma 0. else ma ;
    vy_min.(pi) <- if force_show_0 then min mi 0. else mi ;
    if stacked.(pi) = StackedCentered then (
      vy_max.(pi) <- vy_max.(pi) *. 0.5 ;
      vy_min.(pi) <- -. vy_max.(pi)) ;
    if vy_max.(pi) -. vy_min.(pi) < 1e-10 then (
      vy_max.(pi) <- vy_max.(pi) +. 1. ;
      vy_min.(pi) <- vy_min.(pi) -. 1.)
  done ;
  let get_x    = get_ratio x_axis_xmin x_axis_xmax vx_min vx_max
  and get_y pi = get_ratio y_axis_ymin y_axis_ymax vy_min.(pi) vy_max.(pi) in
  (* In case we stack the values (only primary axis can be stacked since
   * secondary axis can have only one plot) *)
  let prev_vy =
    if stacked.(0) = StackedCentered then
      (* Start from -0.5 * tot_y for this bucket *)
      Array.init nb_vx (fun i -> ~-.0.5 *. max_vy.(0).(i))
    else
      Array.make nb_vx 0. in
  (* per chart infos *)
  let tot_vy = shash.create ()
  and tot_vys = ref 0. in
  iter_datasets (fun pen prim get ->
    if prim then for i = 0 to nb_vx-1 do
      let vy = get i in
      tot_vys := !tot_vys +. vy ;
      match shash.find tot_vy pen.label with
      | None -> shash.add tot_vy pen.label vy
      | Some base -> shash.add tot_vy pen.label (base +. vy)
    done) ;
  RamenFormats.reset_all_states () ;
  (* The SVG *)
  let path_of_dataset pen prim get =
    let pi = if prim then 0 else 1 in
    let is_stacked = stacked.(pi) <> NotStacked && prim in
    let label_str = string_of_label pen.label in
    let p = [] in
    let p = if pen.draw_line then (
      path ~stroke:pen.color
         ~stroke_width:pen.stroke_width
         ~stroke_opacity:pen.opacity
         ?stroke_dasharray:pen.dasharray
         ~fill:(if pen.filled then pen.color else "none")
         ?fill_opacity:(if pen.filled then Some pen.fill_opacity else None)
         ~attrs:[clss ("fitem "^ label_str)]
        (
          let buf = Buffer.create 100 in (* to write path commands in *)
          (* Top line *)
          for i = 0 to nb_vx-1 do
            let vy' = (get i |> rate_of_vy) +. (if is_stacked then prev_vy.(i) else 0.) in
            Buffer.add_string buf
              ((if i = 0 then moveto else lineto)
               (get_x (vx_of_bucket i),
                get_y pi vy'))
          done ;
          if pen.filled || is_stacked then (
            (* Bottom line (to close the area) (note: we loop here from last to first) *)
            for i = nb_vx-1 downto 0 do
              let vy' = prev_vy.(i) in
              if is_stacked then
                prev_vy.(i) <- vy' +. (get i |> rate_of_vy) ;
              Buffer.add_string buf
                (lineto (get_x (vx_of_bucket i), get_y pi vy'))
            done ;
            Buffer.add_string buf closepath) ;
          Buffer.contents buf
        )
      )::p else p in
    let p = if pen.draw_points then (
        (* TODO *) p
      ) else p in
    g [] p in
  let avg_char_width = 0.6 in
  let nb_y, max_label_width = fold.fold (fun (nb_y, w) pen _prim _get ->
    let label_str = string_of_label pen.label in
    let label_width = legend_font_size *. avg_char_width *.
                      float_of_int (String.length label_str) in
    nb_y +. 1., max w label_width) (0., 0.) in
  let legend_row_height = legend_font_size *. 1.2 in
  let inner_margin_horiz = legend_row_height *. 0.2 in
  let inner_margin_vert = inner_margin_horiz in
  let legend_box_width = legend_font_size *. 2. in
  let legend_width = inner_margin_horiz *. 2. +. legend_box_width
                   +. max_label_width in
  let outer_margin = 10. in
  let outer_margin_horiz, outer_margin_vert = match draw_legend with
    | NoShow -> 0., 0.
    | Absolute (x, y) -> x, y
    | UpperLeft -> outer_margin, outer_margin
    | UpperRight -> svg_width -. outer_margin -.  legend_width,
                    outer_margin
    | BottomLeft -> outer_margin,
                    svg_height -. outer_margin -. nb_y *. legend_row_height
    | BottomRight -> svg_width -. outer_margin -.  legend_width,
                     svg_height -. outer_margin -. nb_y *. legend_row_height in
  let legend_of_dataset (nb_y1, nb_y2, width, svg) pen prim _get =
    let label_str = string_of_label pen.label in
    let label_width =
      legend_font_size *. 0.6 *. float_of_int (String.length label_str) in
    let row_width = legend_box_width +. label_width in
    let width = max width row_width in
    let nb_y = float_of_int (nb_y1 + nb_y2) in
    let y = outer_margin_vert +. inner_margin_vert +. legend_row_height *. nb_y in
    let s = g [] [
      rect ~fill:pen.color ~fill_opacity:1.
           ~stroke_width:1. ~stroke:"#000"
           (outer_margin_horiz +. inner_margin_horiz) y
           legend_box_width legend_font_size ;
      svgtext ~x:(outer_margin_horiz +. inner_margin_horiz +. legend_box_width +. 2.)
           ~y:(y +. legend_font_size) ~font_size:legend_font_size label_str
    ] in
    if prim then nb_y1+1, nb_y2, width, s::svg
            else nb_y1, nb_y2+1, width, s::svg in
  let y2 =
    match !label2 with
    | None -> None
    | Some label ->
      Some (string_of_label label, string_of_y2, vy_min.(1), vy_max.(1)) in
  let grid = xy_grid ~stroke:"#000" ~stroke_width:2.
                     ~font_size:axis_font_size
                     ~arrow_size:axis_arrow_h ~x_tick_spacing ~y_tick_spacing
                     ~tick_length ~x_label ~y_label:y_label_grid
                     ?string_of_x ~string_of_y ?y2 ?x_base ?y1_base ?y2_base
                     (x_axis_xmin, x_axis_xmax) (y_axis_ymin, y_axis_ymax)
                     (vx_min, vx_max) (vy_min.(0), vy_max.(0))
  and paths = g [] (map_datasets path_of_dataset)
  and legend =
    if draw_legend <> NoShow then (
      let nb_y1, nb_y2, width, boxes =
        fold.fold legend_of_dataset (0, 0, 0., []) in
      g [] (rect ~fill:"#ddd" ~fill_opacity:0.7 ~stroke_width:0.
              outer_margin_horiz outer_margin_vert
              (inner_margin_horiz *. 2. +. width)
              (inner_margin_vert *. 2. +. (float_of_int (nb_y1 + nb_y2)) *. legend_row_height) ::
         boxes)
    ) else g [] [] in
  (* FIXME: xy_plot should return what's inside the SVG, so that we can compose
   * various components, and stop accept attrs as a parameter *)
  svg svg_width svg_height attrs [ grid ; paths ; legend ]

(* Chronology: represent events with their duration along the time axis,
 * each event can have internal markers. *)

type bar =
  { start : float option ; stop : float option ;
    color : string ;
    markers : (float * string) list }

let chronology ?(svg_width=800.) ?(svg_height=600.)
               ?(axis_font_size=14.) ?(axis_arrow_h=11.)
               ?(x_tick_spacing=180.) ?(tick_length=5.5)
               ?(margin_bottom=30.) ?(margin_left=10.)
               ?(margin_top=30.) ?(margin_right=10.)
               ?click_on_bar ?string_of_t
               bars vx_min vx_max =
  let nb_bars = List.length bars in
  let x_axis_xmin = margin_left
  and x_axis_xmax = svg_width -. margin_right
  (* Counter-intuitively, y_axis_ymin is greater than y_axis_ymax,
   * since ymin is the "start" of the Y axis, which is at the bottom of
   * the SVG. *)
  and y_axis_ymin = svg_height -. margin_bottom -. axis_font_size *. 1.2
  and y_axis_ymax = margin_top in
  let bar_height = (y_axis_ymin -. y_axis_ymax) /. float_of_int nb_bars in
  let x_of =
    let ratio = (x_axis_xmax -. x_axis_xmin) /. (vx_max -. vx_min) in
    fun ts -> x_axis_xmin +. (ts -. vx_min) *. ratio
  and y_of i = y_axis_ymin -. float_of_int i *. bar_height in
  let mark_text_height = 9. in
  let nb_texts_lines_in_bar =
    int_of_float (bar_height /. mark_text_height) in
  let mark_textline_height = (* expand to spread lines evenly *)
    bar_height /. float_of_int nb_texts_lines_in_bar in
  RamenFormats.reset_all_states () ;
  let x_axis =
    axis ~stroke:"#000" ~stroke_width:2.
         ~arrow_size:axis_arrow_h ~tick_spacing:x_tick_spacing
         ~font_size:axis_font_size ~tick_length
         ~label:"time" ?string_of_v:string_of_t
         (x_axis_xmin, y_axis_ymin) (x_axis_xmax, y_axis_ymin)
         vx_min vx_max in
  let svg_of_bar i b =
    let x_start =
      match b.start with None -> ~-.9. | Some s -> x_of s
    and x_stop =
      match b.stop with None -> svg_width +. 9. | Some s -> x_of s
    and y_start = y_of (i+1) and y_stop = y_of i in
    let bar =
      rect ~fill:b.color ~stroke:b.color ~fill_opacity:0.7 ~stroke_width:1.
           x_start y_start (x_stop -. x_start) (y_stop -. y_start)
    and marks =
      List.mapi (fun i (t, s) ->
        let x = x_of t in
        let y_text = y_start +.
          float_of_int (1 + (i mod nb_texts_lines_in_bar)) *.
          mark_textline_height in
        g [] [ line ~stroke:"#000" ~stroke_width:1. ~stroke_opacity:1.
                    ~stroke_dasharray:"1,3" (x, y_start) (x, y_stop) ;
            svgtext ~x:(x+.4.) ~y:y_text ~font_size:mark_text_height
                    ~fill:"#000" s ]
        ) b.markers in
    let action = match click_on_bar with
      | None -> None
      | Some a -> Some (fun _ -> a i) in
    g ?action [] (bar :: marks) in
  let rects = List.mapi svg_of_bar bars in
  g [] [ x_axis ; g [] rects ]

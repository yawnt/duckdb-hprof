use std::collections::HashMap;
use std::io::{Cursor, Read};


use quack_rs::prelude::*;


#[derive(Debug, Default, Clone)]
struct HprofDump {
    format: String,
    id_size: u32,
    timestamp_ms: i64,
    strings: Vec<StringRecord>,
    classes: Vec<LoadClassRecord>,
    class_dumps: Vec<ClassDumpRecord>,
    instances: Vec<InstanceDumpRecord>,
    object_arrays: Vec<ObjectArrayRecord>,
    primitive_arrays: Vec<PrimitiveArrayRecord>,
    gc_roots: Vec<GcRootRecord>,
    heap_summaries: Vec<HeapSummaryRecord>,
    stack_frames: Vec<StackFrame>,
    stack_traces: Vec<StackTrace>,
    dominators: Vec<(u64, u64, u32)>,
}

#[derive(Debug, Clone)] struct StringRecord { id: u64, value: String }
#[derive(Debug, Clone)] struct LoadClassRecord { class_serial: u32, object_id: u64, stack_trace_serial: u32, name_string_id: u64 }
#[derive(Debug, Clone)] struct ClassDumpRecord { class_object_id: u64, stack_trace_serial: u32, super_class_object_id: u64, class_loader_object_id: u64, instance_size: u32, instance_field_count: u16, static_field_count: u16 }
#[derive(Debug, Clone)] struct InstanceDumpRecord { object_id: u64, stack_trace_serial: u32, class_object_id: u64, shallow_size: u32, field_refs: Vec<u64>, retained_size: u64 }
#[derive(Debug, Clone)] struct ObjectArrayRecord { array_object_id: u64, stack_trace_serial: u32, num_elements: u32, array_class_id: u64, element_ids: Vec<u64> }
#[derive(Debug, Clone)] struct PrimitiveArrayRecord { array_object_id: u64, stack_trace_serial: u32, num_elements: u32, element_type: u8 }
#[derive(Debug, Clone)] struct GcRootRecord { root_type: String, object_id: u64, thread_serial: Option<u32>, frame_number: Option<u32>, jni_global_ref_id: Option<u64> }
#[derive(Debug, Clone)] struct HeapSummaryRecord { total_live_bytes: u32, total_live_instances: u32, total_alloc_bytes: u64, total_alloc_instances: u64 }
#[derive(Debug, Clone)] struct StackFrame { frame_id: u64, method_name_id: u64, method_sig_id: u64, source_file_id: u64, class_serial: u32, line_number: i32 }
#[derive(Debug, Clone)] struct StackTrace { trace_serial: u32, thread_serial: u32, frame_ids: Vec<u64> }

fn r8(c: &mut Cursor<Vec<u8>>) -> std::io::Result<u8> { let mut b = [0u8; 1]; c.read_exact(&mut b)?; Ok(b[0]) }
fn r16(c: &mut Cursor<Vec<u8>>) -> std::io::Result<u16> { let mut b = [0u8; 2]; c.read_exact(&mut b)?; Ok(u16::from_be_bytes(b)) }
fn r32(c: &mut Cursor<Vec<u8>>) -> std::io::Result<u32> { let mut b = [0u8; 4]; c.read_exact(&mut b)?; Ok(u32::from_be_bytes(b)) }
fn r64(c: &mut Cursor<Vec<u8>>) -> std::io::Result<u64> { let mut b = [0u8; 8]; c.read_exact(&mut b)?; Ok(u64::from_be_bytes(b)) }
fn rid(c: &mut Cursor<Vec<u8>>, is: u32) -> std::io::Result<u64> { match is { 4 => Ok(r32(c)? as u64), 8 => r64(c), _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad id_size")) } }
fn bts(t: u8, is: u32) -> usize { match t { 2 => is as usize, 4 | 8 => 1, 5 | 9 => 2, 6 | 10 => 4, 7 | 11 => 8, _ => 0 } }

fn try_read_header(c: &mut Cursor<Vec<u8>>) -> std::io::Result<Option<(u8, usize)>> {
    let tag = match r8(c) {
        Ok(t) => t,
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let _time = r32(c)?;
    let raw_len = r32(c)? as usize;
    let remaining = c.get_ref().len() - c.position() as usize;
    Ok(Some((tag, if raw_len > remaining { remaining } else { raw_len })))
}

fn parse_hprof(data: Vec<u8>) -> Result<HprofDump, Box<dyn std::error::Error>> {
    if data.len() < 14 { return Err("too small".into()); }
    let null_pos = data.iter().position(|&b| b == 0).ok_or("bad magic")?;
    let format = String::from_utf8_lossy(&data[..null_pos]).into_owned();
    let pos = null_pos + 1;
    let id_size = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    let timestamp_ms = i64::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7], data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);

    let mut c = Cursor::new(data);
    c.set_position((pos + 12) as u64);
    let mut dump = HprofDump { format, id_size, timestamp_ms, ..Default::default() };
    let mut class_fields: HashMap<u64, Vec<u8>> = HashMap::new();
    while let Some((tag, len)) = try_read_header(&mut c)? {
        let ds = c.position();
        let de = ds as usize + len;
        match tag {
            0x01 if len >= id_size as usize => {
                if let Ok(id) = rid(&mut c, id_size) {
                    let vl = len - id_size as usize;
                    let mut buf = vec![0u8; vl];
                    if c.read_exact(&mut buf).is_ok() {
                        dump.strings.push(StringRecord { id, value: String::from_utf8_lossy(&buf).into_owned() });
                    }
                }
            }
            0x02 => {
                if let (Ok(cs), Ok(oi), Ok(st), Ok(ni)) = (r32(&mut c), rid(&mut c, id_size), r32(&mut c), rid(&mut c, id_size)) {
                    dump.classes.push(LoadClassRecord { class_serial: cs, object_id: oi, stack_trace_serial: st, name_string_id: ni });
                }
            }
            0x08 if len >= 24 => {
                if let (Ok(a), Ok(b), Ok(cc), Ok(dd)) = (r32(&mut c), r32(&mut c), r64(&mut c), r64(&mut c)) {
                    dump.heap_summaries.push(HeapSummaryRecord { total_live_bytes: a, total_live_instances: b, total_alloc_bytes: cc, total_alloc_instances: dd });
                }
            }
            0x23..=0x2C => {
                if let Ok(oi) = rid(&mut c, id_size) {
                    let (rt, ts, fn2, jr) = match tag {
                        0x23 => ("UNKNOWN", None, None, None),
                        0x24 => ("THREAD_OBJECT", r32(&mut c).ok(), None, None),
                        0x25 => ("JNI_GLOBAL", None, None, rid(&mut c, id_size).ok()),
                        0x26 => ("JNI_LOCAL", r32(&mut c).ok(), r32(&mut c).ok(), None),
                        0x27 => ("JAVA_FRAME", r32(&mut c).ok(), r32(&mut c).ok(), None),
                        0x28 => ("NATIVE_STACK", r32(&mut c).ok(), None, None),
                        0x29 => ("STICKY_CLASS", None, None, None),
                        0x2A => ("THREAD_BLOCK", r32(&mut c).ok(), None, None),
                        0x2B => ("MONITOR_USED", None, None, None),
                        0x2C => ("THREAD_OBJECT", r32(&mut c).ok(), None, None),
                        _ => unreachable!(),
                    };
                    dump.gc_roots.push(GcRootRecord { root_type: rt.to_string(), object_id: oi, thread_serial: ts, frame_number: fn2, jni_global_ref_id: jr });
                }
            }
            0x0C | 0x1C => {
                let _ = parse_heap_dump(&mut c, id_size, de, &mut class_fields, &mut dump);
            }
            0x04 if len >= id_size as usize * 4 + 8 => {
                if let (Ok(fid), Ok(mn), Ok(ms), Ok(sf), Ok(cs)) = (rid(&mut c, id_size), rid(&mut c, id_size), rid(&mut c, id_size), rid(&mut c, id_size), r32(&mut c)) {
                    let ln = r32(&mut c).unwrap_or(0) as i32;
                    dump.stack_frames.push(StackFrame { frame_id: fid, method_name_id: mn, method_sig_id: ms, source_file_id: sf, class_serial: cs, line_number: ln });
                }
            }
            0x05 => {
                if let (Ok(ts), Ok(th)) = (r32(&mut c), r32(&mut c)) {
                    let nf = r32(&mut c).unwrap_or(0) as usize;
                    let mut fids = Vec::with_capacity(nf);
                    for _ in 0..nf { if let Ok(fid) = rid(&mut c, id_size) { fids.push(fid); } }
                    dump.stack_traces.push(StackTrace { trace_serial: ts, thread_serial: th, frame_ids: fids });
                }
            }
            _ => {}
        }
        c.set_position(de as u64);
    }
    compute_retained(&mut dump);

    Ok(dump)
}

fn compute_retained(dump: &mut HprofDump) {
    let id_size = dump.id_size as u64;
    let mut successors: HashMap<u64, Vec<u64>> = HashMap::new();
    for r in &dump.gc_roots { successors.entry(r.object_id).or_default(); }
    for inst in &dump.instances { if !inst.field_refs.is_empty() { successors.insert(inst.object_id, inst.field_refs.clone()); } }
    for arr in &dump.object_arrays { if arr.element_ids.len() < 100_000 { successors.insert(arr.array_object_id, arr.element_ids.clone()); } }
    for cd in &dump.class_dumps {
        if cd.super_class_object_id != 0 { successors.entry(cd.class_object_id).or_default().push(cd.super_class_object_id); }
        if cd.class_loader_object_id != 0 { successors.entry(cd.class_object_id).or_default().push(cd.class_loader_object_id); }
    }
    let has_incoming: std::collections::HashSet<u64> = successors.values().flat_map(|v| v.iter().copied()).collect();
    let mut roots: Vec<u64> = dump.gc_roots.iter().map(|r| r.object_id).collect();
    for key in successors.keys() { if !has_incoming.contains(key) { roots.push(*key); } }
    roots.sort(); roots.dedup();

    let mut shallow: HashMap<u64, u64> = HashMap::new();
    for inst in &dump.instances { shallow.insert(inst.object_id, inst.shallow_size as u64); }
    for arr in &dump.object_arrays { shallow.insert(arr.array_object_id, ((arr.num_elements as u64 * id_size + 2 * id_size + 4) + 7) & !7); }
    for arr in &dump.primitive_arrays {
        let esz = if arr.element_type == 5 { 2 } else { bts(arr.element_type, 1) };
        shallow.insert(arr.array_object_id, ((arr.num_elements as u64 * esz as u64 + 2 * id_size + 4) + 7) & !7);
    }

    let idom = compute_dominators(&roots, &successors);
    let mut dom_children: HashMap<u64, Vec<u64>> = HashMap::new();
    for (&node, &dom) in &idom { dom_children.entry(dom).or_default().push(node); }
    let dominated: std::collections::HashSet<u64> = idom.keys().copied().collect();
    let mut dist: HashMap<u64, u32> = HashMap::new();
    for &node in shallow.keys() { if !dominated.contains(&node) { dist.insert(node, 0); } }
    let mut queue: Vec<u64> = dist.keys().copied().collect();
    let mut qi = 0;
    while qi < queue.len() {
        let node = queue[qi]; qi += 1;
        let d = dist[&node] + 1;
        if let Some(kids) = dom_children.get(&node) { for &kid in kids { dist.insert(kid, d); queue.push(kid); } }
    }

    let mut retained: HashMap<u64, u64> = HashMap::new();
    for &node in queue.iter().rev() {
        let s = shallow.get(&node).copied().unwrap_or(0)
            + dom_children.get(&node).map(|k| k.iter().map(|&k| retained.get(&k).copied().unwrap_or(0)).sum::<u64>()).unwrap_or(0);
        retained.insert(node, s);
    }
    for inst in &mut dump.instances { inst.retained_size = retained.get(&inst.object_id).copied().unwrap_or(inst.shallow_size as u64); }

    let mut all_dominators: Vec<(u64, u64, u32)> = idom.iter()
        .map(|(&obj, &dom)| (obj, dom, dist.get(&obj).copied().unwrap_or(0))).collect();
    for &node in shallow.keys() { if !dominated.contains(&node) { all_dominators.push((node, 0, 0)); } }
    dump.dominators = all_dominators;
}

fn parse_heap_dump(c: &mut Cursor<Vec<u8>>, id_size: u32, end_pos: usize, class_fields: &mut HashMap<u64, Vec<u8>>, dump: &mut HprofDump) -> Result<(), ()> {
    let mut sub_count = 0u64;
    while (c.position() as usize) < end_pos {
        sub_count += 1;
        if sub_count > 200000 { return Err(()); }
        let sub_tag = r8(c).map_err(|_| ())?;
        match sub_tag {
            0x01 => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                dump.gc_roots.push(GcRootRecord { root_type: "UNKNOWN".into(), object_id: oid, thread_serial: None, frame_number: None, jni_global_ref_id: None });
            }
            0x02 => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                let jr = rid(c, id_size).map_err(|_| ())?;
                dump.gc_roots.push(GcRootRecord { root_type: "JNI_GLOBAL".into(), object_id: oid, thread_serial: None, frame_number: None, jni_global_ref_id: Some(jr) });
            }
            0x03 | 0x04 => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                let ts = r32(c).map_err(|_| ())?;
                let fn2 = r32(c).map_err(|_| ())?;
                let rt = if sub_tag == 0x03 { "JNI_LOCAL" } else { "JAVA_FRAME" };
                dump.gc_roots.push(GcRootRecord { root_type: rt.into(), object_id: oid, thread_serial: Some(ts), frame_number: Some(fn2), jni_global_ref_id: None });
            }
            0x05 | 0x07 => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                let ts = r32(c).map_err(|_| ())?;
                let rt = if sub_tag == 0x05 { "NATIVE_STACK" } else { "THREAD_BLOCK" };
                dump.gc_roots.push(GcRootRecord { root_type: rt.into(), object_id: oid, thread_serial: Some(ts), frame_number: None, jni_global_ref_id: None });
            }
            0x06 | 0x08 => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                let rt = if sub_tag == 0x06 { "STICKY_CLASS" } else { "MONITOR_USED" };
                dump.gc_roots.push(GcRootRecord { root_type: rt.into(), object_id: oid, thread_serial: None, frame_number: None, jni_global_ref_id: None });
            }
            0x09 | 0x0A => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                let ts = r32(c).map_err(|_| ())?;
                let sts = r32(c).map_err(|_| ())?;
                let rt = if sub_tag == 0x09 { "THREAD_OBJECT" } else { "JNI_MONITOR" };
                dump.gc_roots.push(GcRootRecord { root_type: rt.into(), object_id: oid, thread_serial: Some(ts), frame_number: Some(sts), jni_global_ref_id: None });
            }
            0x20 => {
                let coid = rid(c, id_size).map_err(|_| ())?;
                let sts = r32(c).map_err(|_| ())?;
                let scoid = rid(c, id_size).map_err(|_| ())?;
                let cloid = rid(c, id_size).map_err(|_| ())?;
                rid(c, id_size).map_err(|_| ())?; // signers
                rid(c, id_size).map_err(|_| ())?; // protection_domain
                rid(c, id_size).map_err(|_| ())?; // reserved1
                rid(c, id_size).map_err(|_| ())?; // reserved2
                let isz = r32(c).map_err(|_| ())?;
                let cp_sz = r16(c).map_err(|_| ())?;
                for _ in 0..cp_sz { r16(c).map_err(|_| ())?; let ct = r8(c).map_err(|_| ())?; c.set_position(c.position() + bts(ct, id_size) as u64); }
                let ns = r16(c).map_err(|_| ())?;
                for _ in 0..ns { rid(c, id_size).map_err(|_| ())?; let st = r8(c).map_err(|_| ())?; c.set_position(c.position() + bts(st, id_size) as u64); }
                let nf = r16(c).map_err(|_| ())?;
                let mut ftypes = Vec::with_capacity(nf as usize);
                for _ in 0..nf { rid(c, id_size).map_err(|_| ())?; ftypes.push(r8(c).map_err(|_| ())?); }
                class_fields.insert(coid, ftypes);
                dump.class_dumps.push(ClassDumpRecord { class_object_id: coid, stack_trace_serial: sts, super_class_object_id: scoid, class_loader_object_id: cloid, instance_size: isz, instance_field_count: nf, static_field_count: ns });
            }
            0x21 => {
                let oid = rid(c, id_size).map_err(|_| ())?;
                let sts = r32(c).map_err(|_| ())?;
                let coid = rid(c, id_size).map_err(|_| ())?;
                let raw_data_bytes = r32(c).map_err(|_| ())?; // u4: field data byte count
                let data_start = c.position();
                let data_bytes = (raw_data_bytes as u64).min((end_pos as u64).saturating_sub(data_start));
                let mut refs = Vec::new();
                if let Some(ftypes) = class_fields.get(&coid) {
                    for &ft in ftypes {
                        if ft == 2 { if let Ok(r) = rid(c, id_size) { refs.push(r); } }
                        else { c.set_position(c.position() + bts(ft, id_size) as u64); }
                    }

                }
                c.set_position(data_start + data_bytes);
                let header = 2 * id_size; // mark word + klass pointer
                let shallow = ((header + data_bytes as u32) + 7) & !7; // align to 8
                dump.instances.push(InstanceDumpRecord { object_id: oid, stack_trace_serial: sts, class_object_id: coid, shallow_size: shallow, field_refs: refs, retained_size: 0 });
            }0x22 => {
                let aoid = rid(c, id_size).map_err(|_| ())?;
                let sts = r32(c).map_err(|_| ())?;
                let n = r32(c).map_err(|_| ())?;
                let acid = rid(c, id_size).map_err(|_| ())?;
                let mut eids = Vec::with_capacity(n as usize);
                for _ in 0..n { if let Ok(eid) = rid(c, id_size) { eids.push(eid); } }
                dump.object_arrays.push(ObjectArrayRecord { array_object_id: aoid, stack_trace_serial: sts, num_elements: n, array_class_id: acid, element_ids: eids });
            }
            0x23 => {
                let aoid = rid(c, id_size).map_err(|_| ())?;
                let sts = r32(c).map_err(|_| ())?;
                let n = r32(c).map_err(|_| ())?;
                let et = r8(c).map_err(|_| ())?;
                c.set_position(c.position() + (n as usize * if et == 5 { 2 } else { bts(et, 1) }) as u64);
                dump.primitive_arrays.push(PrimitiveArrayRecord { array_object_id: aoid, stack_trace_serial: sts, num_elements: n, element_type: et });
            }
            0xFE => { r32(c).map_err(|_| ())?; rid(c, id_size).map_err(|_| ())?; }
            0xFF => { rid(c, id_size).map_err(|_| ())?; }
            _ => { c.set_position(end_pos as u64); return Ok(()); }
        }
    }
    Ok(())
}


enum TableKind { Header, Strings, Classes, ClassDumps, Instances, GcRoots, HeapSummary, ObjectArrays, PrimitiveArrays, StackFrames, StackTraces, Dominators }

struct ScanState { dump: HprofDump, kind: TableKind, row: usize, array_idx: usize, elem_idx: usize }

macro_rules! slice_scan {
    ($st:expr, $ch:expr, $field:ident, |$i:ident, $r:ident| $body:block) => {{
        let data = &$st.dump.$field;
        let n = (data.len() - $st.row).min(2048);
        if n == 0 { unsafe { $ch.set_size(0) }; return Ok(()); }
        for $i in 0..n { let $r = &data[$st.row + $i]; $body }
        $st.row += n; unsafe { $ch.set_size(n) }; Ok(())
    }};
}

fn hprof_scan_reg(reg: &impl Registrar) -> ExtResult<()> {
    let builder = TableFunctionBuilder::new("hprof_scan")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .with_state::<ScanState, _>(|bind| {
            let path = unsafe { bind.get_parameter_value(0) }.as_str().unwrap_or_default().to_string();
            let table = unsafe { bind.get_parameter_value(1) }.as_str().unwrap_or_default();
            let data = std::fs::read(&path).map_err(|e| e.to_string())?;
            let dump = parse_hprof(data).map_err(|e| e.to_string())?;
            let kind = match table.as_str() {
                "header" => { bind.add_result_column("format", TypeId::Varchar); bind.add_result_column("id_size", TypeId::Integer); bind.add_result_column("timestamp_ms", TypeId::BigInt); TableKind::Header }
                "strings" => { bind.add_result_column("string_id", TypeId::UBigInt); bind.add_result_column("value", TypeId::Varchar); TableKind::Strings }
                "classes" => { bind.add_result_column("class_serial", TypeId::Integer); bind.add_result_column("class_object_id", TypeId::UBigInt); bind.add_result_column("stack_trace_serial", TypeId::Integer); bind.add_result_column("name_string_id", TypeId::UBigInt); TableKind::Classes }
                "class_dumps" => { bind.add_result_column("class_object_id", TypeId::UBigInt); bind.add_result_column("stack_trace_serial", TypeId::Integer); bind.add_result_column("super_class_object_id", TypeId::UBigInt); bind.add_result_column("class_loader_object_id", TypeId::UBigInt); bind.add_result_column("instance_size", TypeId::Integer); bind.add_result_column("instance_field_count", TypeId::SmallInt); bind.add_result_column("static_field_count", TypeId::SmallInt); TableKind::ClassDumps }
                "instances" => { bind.add_result_column("object_id", TypeId::UBigInt); bind.add_result_column("stack_trace_serial", TypeId::Integer); bind.add_result_column("class_object_id", TypeId::UBigInt); bind.add_result_column("shallow_size", TypeId::Integer); bind.add_result_column("retained_size", TypeId::UBigInt); TableKind::Instances }
                "gc_roots" => { bind.add_result_column("root_type", TypeId::Varchar); bind.add_result_column("object_id", TypeId::UBigInt); bind.add_result_column("thread_serial", TypeId::Integer); bind.add_result_column("frame_number", TypeId::Integer); bind.add_result_column("jni_global_ref_id", TypeId::UBigInt); TableKind::GcRoots }
                "heap_summary" => { bind.add_result_column("total_live_bytes", TypeId::Integer); bind.add_result_column("total_live_instances", TypeId::Integer); bind.add_result_column("total_alloc_bytes", TypeId::UBigInt); bind.add_result_column("total_alloc_instances", TypeId::UBigInt); TableKind::HeapSummary }
                "object_arrays" => { bind.add_result_column("array_object_id", TypeId::UBigInt); bind.add_result_column("stack_trace_serial", TypeId::Integer); bind.add_result_column("num_elements", TypeId::Integer); bind.add_result_column("array_class_id", TypeId::UBigInt); bind.add_result_column("element_index", TypeId::Integer); bind.add_result_column("element_id", TypeId::UBigInt); TableKind::ObjectArrays }
                "primitive_arrays" => { bind.add_result_column("array_object_id", TypeId::UBigInt); bind.add_result_column("stack_trace_serial", TypeId::Integer); bind.add_result_column("num_elements", TypeId::Integer); bind.add_result_column("element_type", TypeId::Varchar); bind.add_result_column("total_bytes", TypeId::Integer); TableKind::PrimitiveArrays }
                "stack_frames" => { bind.add_result_column("frame_id", TypeId::UBigInt); bind.add_result_column("method_name_id", TypeId::UBigInt); bind.add_result_column("method_sig_id", TypeId::UBigInt); bind.add_result_column("source_file_id", TypeId::UBigInt); bind.add_result_column("class_serial", TypeId::Integer); bind.add_result_column("line_number", TypeId::Integer); TableKind::StackFrames }
                "stack_traces" => { bind.add_result_column("trace_serial", TypeId::Integer); bind.add_result_column("thread_serial", TypeId::Integer); bind.add_result_column("frame_count", TypeId::Integer); TableKind::StackTraces }
                "dominators" => { bind.add_result_column("object_id", TypeId::UBigInt); bind.add_result_column("dominator_id", TypeId::UBigInt); bind.add_result_column("distance_to_root", TypeId::Integer); TableKind::Dominators }
                _ => return Err(format!("unknown table: {table}. Valid: header, strings, classes, class_dumps, instances, gc_roots, heap_summary, object_arrays, primitive_arrays, stack_frames, stack_traces, dominators").into()),
            };
            Ok(ScanState { dump, kind, row: 0, array_idx: 0, elem_idx: 0 })
        })
        .scan(|state, chunk| {
            match state.kind {
                TableKind::Header => {
                    if state.row >= 1 { unsafe { chunk.set_size(0) }; return Ok(()); }
                    unsafe { chunk.writer(0).write_str(0, &state.dump.format) };
                    unsafe { chunk.writer(1).write_i32(0, state.dump.id_size as i32) };
                    unsafe { chunk.writer(2).write_i64(0, state.dump.timestamp_ms) };
                    state.row += 1; unsafe { chunk.set_size(1) }; Ok(())
                }
                TableKind::Strings => slice_scan!(state, chunk, strings, |i, r| {
                    unsafe { chunk.writer(0).write_u64(i, r.id); chunk.writer(1).write_str(i, &r.value); }
                }),
                TableKind::Classes => slice_scan!(state, chunk, classes, |i, r| {
                    unsafe { chunk.writer(0).write_u32(i, r.class_serial); chunk.writer(1).write_u64(i, r.object_id); chunk.writer(2).write_u32(i, r.stack_trace_serial); chunk.writer(3).write_u64(i, r.name_string_id); }
                }),
                TableKind::ClassDumps => slice_scan!(state, chunk, class_dumps, |i, r| {
                    unsafe { chunk.writer(0).write_u64(i, r.class_object_id); chunk.writer(1).write_u32(i, r.stack_trace_serial); chunk.writer(2).write_u64(i, r.super_class_object_id); chunk.writer(3).write_u64(i, r.class_loader_object_id); chunk.writer(4).write_u32(i, r.instance_size); chunk.writer(5).write_i16(i, r.instance_field_count as i16); chunk.writer(6).write_i16(i, r.static_field_count as i16); }
                }),
                TableKind::Instances => slice_scan!(state, chunk, instances, |i, r| {
                    unsafe { chunk.writer(0).write_u64(i, r.object_id); chunk.writer(1).write_u32(i, r.stack_trace_serial); chunk.writer(2).write_u64(i, r.class_object_id); chunk.writer(3).write_u32(i, r.shallow_size); chunk.writer(4).write_u64(i, r.retained_size); }
                }),
                TableKind::GcRoots => {
                    let data = &state.dump.gc_roots; let rem = data.len() - state.row; let n = rem.min(2048);
                    if n == 0 { unsafe { chunk.set_size(0) }; return Ok(()); }
                    for i in 0..n { let r = &data[state.row + i];
                        unsafe { chunk.writer(0).write_str(i, &r.root_type); chunk.writer(1).write_u64(i, r.object_id); }
                        match r.thread_serial { Some(v) => unsafe { chunk.writer(2).write_u32(i, v) }, None => unsafe { chunk.writer(2).set_null(i) } }
                        match r.frame_number { Some(v) => unsafe { chunk.writer(3).write_u32(i, v) }, None => unsafe { chunk.writer(3).set_null(i) } }
                        match r.jni_global_ref_id { Some(v) => unsafe { chunk.writer(4).write_u64(i, v) }, None => unsafe { chunk.writer(4).set_null(i) } }
                    }
                    state.row += n; unsafe { chunk.set_size(n) }; Ok(())
                }
                TableKind::HeapSummary => slice_scan!(state, chunk, heap_summaries, |i, r| {
                    unsafe { chunk.writer(0).write_u32(i, r.total_live_bytes); chunk.writer(1).write_u32(i, r.total_live_instances); chunk.writer(2).write_u64(i, r.total_alloc_bytes); chunk.writer(3).write_u64(i, r.total_alloc_instances); }
                }),
                TableKind::ObjectArrays => {
                    let arrays = &state.dump.object_arrays; let mut written = 0usize;
                    while written < 2048 && state.array_idx < arrays.len() {
                        let arr = &arrays[state.array_idx];
                        while written < 2048 && state.elem_idx < arr.element_ids.len() {
                            let i = written;
                            unsafe { chunk.writer(0).write_u64(i, arr.array_object_id); chunk.writer(1).write_u32(i, arr.stack_trace_serial); chunk.writer(2).write_u32(i, arr.num_elements); chunk.writer(3).write_u64(i, arr.array_class_id); chunk.writer(4).write_u32(i, state.elem_idx as u32); chunk.writer(5).write_u64(i, arr.element_ids[state.elem_idx]); }
                            state.elem_idx += 1; written += 1;
                        }
                        if state.elem_idx >= arr.element_ids.len() { state.array_idx += 1; state.elem_idx = 0; }
                    }
                    unsafe { chunk.set_size(written) }; Ok(())
                }
                TableKind::PrimitiveArrays => { let tn = ["", "", "object", "", "boolean", "char", "float", "double", "byte", "short", "int", "long"];
                    slice_scan!(state, chunk, primitive_arrays, |i, r| {
                        unsafe { chunk.writer(0).write_u64(i, r.array_object_id); chunk.writer(1).write_u32(i, r.stack_trace_serial); chunk.writer(2).write_u32(i, r.num_elements); chunk.writer(3).write_str(i, tn.get(r.element_type as usize).copied().unwrap_or("unknown")); chunk.writer(4).write_u32(i, (r.num_elements as usize * if r.element_type == 5 { 2 } else { bts(r.element_type, 1) }) as u32); }
                    })
                }
                TableKind::StackFrames => slice_scan!(state, chunk, stack_frames, |i, r| {
                    unsafe { chunk.writer(0).write_u64(i, r.frame_id); chunk.writer(1).write_u64(i, r.method_name_id); chunk.writer(2).write_u64(i, r.method_sig_id); chunk.writer(3).write_u64(i, r.source_file_id); chunk.writer(4).write_u32(i, r.class_serial); chunk.writer(5).write_i32(i, r.line_number); }
                }),
                TableKind::StackTraces => slice_scan!(state, chunk, stack_traces, |i, r| {
                    unsafe { chunk.writer(0).write_u32(i, r.trace_serial); chunk.writer(1).write_u32(i, r.thread_serial); chunk.writer(2).write_u32(i, r.frame_ids.len() as u32); }
                }),
                TableKind::Dominators => slice_scan!(state, chunk, dominators, |i, r| {
                    unsafe { chunk.writer(0).write_u64(i, r.0); chunk.writer(1).write_u64(i, r.1); chunk.writer(2).write_u32(i, r.2); }
                }),
            }
        })
        .build()?;
    unsafe { reg.register_table(builder) }
}


quack_rs::entry_point_v2!(hprof_init_c_api, |con| {
    hprof_scan_reg(con)?;
    Ok(())
});

use petgraph::graph::{Graph, NodeIndex};
use petgraph::algo::dominators;

pub fn compute_dominators(
    roots: &[u64],
    successors: &HashMap<u64, Vec<u64>>,
) -> HashMap<u64, u64> {
    let mut graph = Graph::<u64, ()>::new();
    let mut node_map: HashMap<u64, NodeIndex> = HashMap::new();

    let super_root = graph.add_node(0);

    let mut all_nodes: Vec<u64> = successors.keys().copied().collect();
    for refs in successors.values() {
        for &r in refs {
            all_nodes.push(r);
        }
    }
    for &r in roots {
        all_nodes.push(r);
    }
    all_nodes.sort();
    all_nodes.dedup();

    for &obj in &all_nodes {
        let idx = graph.add_node(obj);
        node_map.insert(obj, idx);
    }

    for &r in roots {
        if let Some(&idx) = node_map.get(&r) {
            graph.add_edge(super_root, idx, ());
        }
    }

    for (&obj, refs) in successors {
        if let Some(&from_idx) = node_map.get(&obj) {
            for &target in refs {
                if let Some(&to_idx) = node_map.get(&target) {
                    graph.add_edge(from_idx, to_idx, ());
                }
            }
        }
    }


    let doms = dominators::simple_fast(&graph, super_root);

    let mut result: HashMap<u64, u64> = HashMap::new();
    for (&obj, &idx) in &node_map {
        if let Some(dom_idx) = doms.immediate_dominator(idx) {
            if dom_idx != super_root {
                let dom_obj = graph[dom_idx];
                if dom_obj != 0 {
                    result.insert(obj, dom_obj);
                }
            }
        }
    }

    result
}


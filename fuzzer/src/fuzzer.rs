// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

use crate::shared_state::GlobalSharedState;
use forksrv::newtypes::SubprocessError;
use forksrv::ForkServer;
use grammartec::context::Context;
use grammartec::tree::TreeLike;
use libafl::events::NopEventManager;
use libafl::executors::Executor;
use libafl::executors::ExitKind;
use libafl::executors::ForkserverExecutor;
use libafl::executors::HasObservers;
use libafl::inputs::BytesInput;
use libafl::inputs::NopTargetBytesConverter;
use libafl::observers::ObserversTuple;
use libafl::observers::StdMapObserver;
use libafl::state::NopState;
use libafl::NopFuzzer;
use libafl_bolts::shmem::UnixShMemProvider;
use libafl_bolts::tuples::Handle;
use libafl_bolts::tuples::MatchNameRef;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fs::File;
use std::io::stdout;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub enum ExecutionReason {
    Havoc,
    HavocRec,
    Min,
    MinRec,
    Splice,
    Det,
    Gen,
}

pub struct Fuzzer<'a> {
    forkserver: ForkserverExecutor<
        NopTargetBytesConverter<BytesInput>,
        (StdMapObserver<'a, u8, false>, ()),
        NopState<BytesInput>,
        UnixShMemProvider,
    >,
    handle: Handle<StdMapObserver<'a, u8, false>>,
    last_tried_inputs: HashSet<Vec<u8>>,
    last_inputs_ring_buffer: VecDeque<Vec<u8>>,
    pub global_state: Arc<Mutex<GlobalSharedState>>,
    pub target_path: String,
    pub target_args: Vec<String>,
    pub execution_count: u64,
    pub average_executions_per_sec: f32,
    pub bits_found_by_havoc: u64,
    pub bits_found_by_havoc_rec: u64,
    pub bits_found_by_min: u64,
    pub bits_found_by_min_rec: u64,
    pub bits_found_by_splice: u64,
    pub bits_found_by_det: u64,
    pub bits_found_by_det_afl: u64,
    pub bits_found_by_gen: u64,
    pub asan_found_by_havoc: u64,
    pub asan_found_by_havoc_rec: u64,
    pub asan_found_by_min: u64,
    pub asan_found_by_min_rec: u64,
    pub asan_found_by_splice: u64,
    pub asan_found_by_det: u64,
    pub asan_found_by_det_afl: u64,
    pub asan_found_by_gen: u64,
    work_dir: String,
}

impl<'a> Fuzzer<'a> {
    pub fn new(
        forkserver: ForkserverExecutor<
            NopTargetBytesConverter<BytesInput>,
            (StdMapObserver<'a, u8, false>, ()),
            NopState<BytesInput>,
            UnixShMemProvider,
        >,
        handle: Handle<StdMapObserver<'a, u8, false>>,
        path: String,
        args: Vec<String>,
        global_state: Arc<Mutex<GlobalSharedState>>,
        work_dir: String,
        timeout_in_millis: u64,
        bitmap_size: usize,
    ) -> Result<Self, SubprocessError> {
        return Ok(Fuzzer {
            forkserver,
            handle,
            last_tried_inputs: HashSet::new(),
            last_inputs_ring_buffer: VecDeque::new(),
            global_state,
            target_path: path,
            target_args: args,
            execution_count: 0,
            average_executions_per_sec: 0.0,
            bits_found_by_havoc: 0,
            bits_found_by_havoc_rec: 0,
            bits_found_by_min: 0,
            bits_found_by_min_rec: 0,
            bits_found_by_splice: 0,
            bits_found_by_det: 0,
            bits_found_by_det_afl: 0,
            bits_found_by_gen: 0,
            asan_found_by_havoc: 0,
            asan_found_by_havoc_rec: 0,
            asan_found_by_min: 0,
            asan_found_by_min_rec: 0,
            asan_found_by_splice: 0,
            asan_found_by_det: 0,
            asan_found_by_det_afl: 0,
            asan_found_by_gen: 0,
            work_dir: work_dir,
        });
    }

    pub fn run_on_with_dedup<T: TreeLike>(
        &mut self,
        tree: &T,
        exec_reason: ExecutionReason,
        ctx: &Context,
    ) -> Result<bool, SubprocessError> {
        let code: Vec<u8> = tree.unparse_to_vec(ctx);
        if self.input_is_known(&code) {
            return Ok(false);
        }
        self.run_on(&code, tree, exec_reason, ctx)?;
        return Ok(true);
    }

    pub fn run_on_without_dedup<T: TreeLike>(
        &mut self,
        tree: &T,
        exec_reason: ExecutionReason,
        ctx: &Context,
    ) -> Result<(), SubprocessError> {
        let code = tree.unparse_to_vec(ctx);
        return self.run_on(&code, tree, exec_reason, ctx);
    }

    fn run_on<T: TreeLike>(
        &mut self,
        code: &Vec<u8>,
        tree: &T,
        exec_reason: ExecutionReason,
        ctx: &Context,
    ) -> Result<(), SubprocessError> {
        let (new_bits, term_sig) = self.exec(code, tree, ctx)?;
        match term_sig {
            ExitKind::Ok => {
                if new_bits.is_some() {
                    match exec_reason {
                        ExecutionReason::Havoc => {
                            self.bits_found_by_havoc += 1; /*print!("Havoc+")*/
                        }
                        ExecutionReason::HavocRec => {
                            self.bits_found_by_havoc_rec += 1; /*print!("HavocRec+")*/
                        }
                        ExecutionReason::Min => {
                            self.bits_found_by_min += 1; /*print!("Min+")*/
                        }
                        ExecutionReason::MinRec => {
                            self.bits_found_by_min_rec += 1; /*print!("MinRec+")*/
                        }
                        ExecutionReason::Splice => {
                            self.bits_found_by_splice += 1; /*print!("Splice+")*/
                        }
                        ExecutionReason::Det => {
                            self.bits_found_by_det += 1; /*print!("Det+")*/
                        }
                        ExecutionReason::Gen => {
                            self.bits_found_by_gen += 1; /*print!("Gen+")*/
                        }
                    }
                }
            }
            ExitKind::Timeout => {
                // LETS IGNORE ALL TIMEOUTS
                /* self.global_state
                    .lock()
                    .expect("RAND_1706238230")
                    .last_timeout =
                    time::strftime("[%Y-%m-%d] %H:%M:%S", &time::now()).expect("RAND_1894162412");
                let mut file = File::create(format!(
                    "{}/outputs/timeout/{:09}",
                    self.work_dir, self.execution_count
                ))
                .expect("RAND_452993103");
                tree.unparse_to(ctx, &mut file); */
            }
            ExitKind::Crash | ExitKind::Oom => {
                if new_bits.is_some() {
                    self.global_state
                        .lock()
                        .expect("RAND_1858328446")
                        .total_found_sig += 1;
                    self.global_state
                        .lock()
                        .expect("RAND_4287051369")
                        .last_found_sig =
                        time::strftime("[%Y-%m-%d] %H:%M:%S", &time::now()).expect("RAND_76391000");
                    let mut file = File::create(format!(
                        "{}/outputs/signaled/{:?}_{:09}",
                        self.work_dir, 0, self.execution_count
                    ))
                    .expect("RAND_3690294970");
                    tree.unparse_to(ctx, &mut file);
                }
            }
            _ => {}
        }
        stdout().flush().expect("RAND_2937475131");
        return Ok(());
    }

    pub fn has_bits<T: TreeLike>(
        &mut self,
        tree: &T,
        bits: &HashSet<usize>,
        exec_reason: ExecutionReason,
        ctx: &Context,
    ) -> Result<bool, SubprocessError> {
        self.run_on_without_dedup(tree, exec_reason, ctx)?;
        let observers = self.forkserver.observers();
        let run_bitmap = observers.get(&self.handle).unwrap().map();
        let mut found_all = true;
        for bit in bits.iter() {
            if run_bitmap[*bit] == 0 {
                //TODO: handle edge counts properly
                found_all = false;
            }
        }
        return Ok(found_all);
    }

    pub fn exec_raw(&mut self, code: &[u8]) -> Result<(ExitKind, u32), SubprocessError> {
        self.execution_count += 1;

        let start = Instant::now();
        if code.len() == 0 {
            return Ok((ExitKind::Ok, 0));
        }
        let input = BytesInput::from(code);
        let _ = self.forkserver.observers_mut().pre_exec_all(&mut NopState::<BytesInput>::new(), &input).unwrap();
        let exitreason = self
            .forkserver
            .run_target(
                &mut NopFuzzer::new(),
                &mut NopState::new(),
                &mut NopEventManager::new(),
                &BytesInput::from(code),
            )
            .unwrap();

        let execution_time = start.elapsed().subsec_nanos();

        self.average_executions_per_sec = self.average_executions_per_sec * 0.9
            + ((1.0 / (execution_time as f32)) * 1000000000.0) * 0.1;

        return Ok((exitreason, execution_time));
    }

    fn input_is_known(&mut self, code: &[u8]) -> bool {
        if self.last_tried_inputs.contains(code) {
            return true;
        } else {
            self.last_tried_inputs.insert(code.to_vec());
            if self.last_inputs_ring_buffer.len() == 10000 {
                self.last_tried_inputs.remove(
                    &self
                        .last_inputs_ring_buffer
                        .pop_back()
                        .expect("No entry in last_inputs_ringbuffer"),
                );
            }
            self.last_inputs_ring_buffer.push_front(code.to_vec());
        }
        return false;
    }

    fn exec<T: TreeLike>(
        &mut self,
        code: &[u8],
        tree_like: &T,
        ctx: &Context,
    ) -> Result<(Option<Vec<usize>>, ExitKind), SubprocessError> {
        let (exitreason, execution_time) = self.exec_raw(&code)?;

        let is_crash = match exitreason {
            ExitKind::Oom => true,
            ExitKind::Crash => true,
            _ => false,
        };

        let mut final_bits = None;
        if let Some(mut new_bits) = self.new_bits(is_crash) {
            //Only if not Timeout
            if exitreason != ExitKind::Timeout {
                //Check for non deterministic bits
                let observers = self.forkserver.observers();
                let old_bitmap = observers.get(&self.handle).unwrap().map().to_vec();
                self.check_deterministic_behaviour(&old_bitmap, &mut new_bits, &code)?;
                if new_bits.len() > 0 {
                    final_bits = Some(new_bits);
                    let tree = tree_like.to_tree(ctx);
                    self.global_state
                        .lock()
                        .expect("RAND_2835014626")
                        .queue
                        .add(tree, old_bitmap, exitreason, ctx, execution_time);
                    //println!("Entry added to queue! New bits: {:?}", bits.clone().expect("RAND_2243482569"));
                }
            }
        }
        return Ok((final_bits, exitreason));
    }

    fn check_deterministic_behaviour(
        &mut self,
        old_bitmap: &[u8],
        new_bits: &mut Vec<usize>,
        code: &[u8],
    ) -> Result<(), SubprocessError> {
        for _ in 0..5 {
            let (_, _) = self.exec_raw(code)?;
            let observers = self.forkserver.observers();
            let run_bitmap = observers.get(&self.handle).unwrap().map();
            for (i, &v) in old_bitmap.iter().enumerate() {
                if run_bitmap[i] != v {
/*                     println!("found fucky bit {}", i); */
                }
            }
            new_bits.retain(|&i| run_bitmap[i] != 0);
        }
        return Ok(());
    }

    pub fn new_bits(&mut self, is_crash: bool) -> Option<Vec<usize>> {
        let mut res = vec![];
        let observers = self.forkserver.observers();
        let run_bitmap = observers.get(&self.handle).unwrap().map();
        let mut gstate_lock = self.global_state.lock().expect("RAND_2040280272");
        let shared_bitmap = gstate_lock
            .bitmaps
            .get_mut(&is_crash)
            .expect("Bitmap missing! Maybe shared state was not initialized correctly?");

        for (i, elem) in shared_bitmap.iter_mut().enumerate() {
            if (run_bitmap[i] != 0) && (*elem == 0) {
                *elem |= run_bitmap[i];
                res.push(i);
/*                 println!("Added new bit to bitmap. Is Crash: {:?}; Added bit: {:?}", is_crash, i); */
            }
        }

        if res.len() > 0 {
            return Some(res);
        } else {
        }
        return None;
    }
}

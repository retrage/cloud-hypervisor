use std::{os::unix::net::UnixListener, sync::mpsc};

use gdbstub::{
    arch::Arch,
    common::Signal,
    conn::{Connection, ConnectionExt},
    stub::{run_blocking, DisconnectReason, SingleThreadStopReason},
    target::{
        ext::{
            base::{
                singlethread::{
                    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps,
                    SingleThreadSingleStep, SingleThreadSingleStepOps,
                },
                BaseOps,
            },
            breakpoints::{Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps},
        },
        Target, TargetError, TargetResult,
    },
};
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::reg::X86_64CoreRegs as CoreRegs;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::X86_64_SSE as GdbArch;
use vm_memory::GuestAddress;

#[cfg(target_arch = "x86_64")]
type ArchUsize = u64;

#[derive(Debug)]
pub enum Error {
    Vm(crate::vm::Error),
    GdbRequest,
    GdbResponseNotify(std::io::Error),
    GdbResponse(mpsc::RecvError),
    GdbResponseTimeout(mpsc::RecvTimeoutError),
}
type GdbResult<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum VmDebugStatus {
    CommandComplete,
    HitBreakPoint,
}

#[derive(Debug)]
pub enum GdbResponsePayload {
    Empty,
    RegValues(Box<CoreRegs>),
    MemoryRegion(Vec<u8>),
    VmDebugStatus(VmDebugStatus),
}

pub type GdbResponse = std::result::Result<GdbResponsePayload, Error>;

#[derive(Debug)]
pub struct GdbRequest {
    pub sender: mpsc::Sender<GdbResponse>,
    pub payload: GdbRequestPayload,
}

#[derive(Debug)]
pub enum GdbRequestPayload {
    ReadRegs,
    WriteRegs(Box<CoreRegs>),
    ReadMem(vm_memory::GuestAddress, usize),
    WriteMem(vm_memory::GuestAddress, Vec<u8>),
    Pause,
    Resume,
    SetSingleStep(bool),
    SetHwBreakPoint(Vec<vm_memory::GuestAddress>),
}

#[repr(u64)]
#[derive(Debug)]
pub enum GdbResponseEventKind {
    ReadRegs = 1,
    WriteRegs,
    ReadMem,
    WriteMem,
    Pause,
    Resume,
    SetSingleStep,
    SetHwBreakPoint,
}

pub fn gdb_thread(mut gdbstub: GdbStub, path: &str) {
    let listener = match UnixListener::bind(path) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create a Unix domain socket listener: {}", e);
            return;
        }
    };
    info!("Waiting for a GDB connection on {}...", path);

    let (stream, addr) = match listener.accept() {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to accept a connection from GDB: {}", e);
            return;
        }
    };
    info!("GDB connected from {:?}", addr);

    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(stream);
    let gdb = gdbstub::stub::GdbStub::new(connection);

    match gdb.run_blocking::<GdbEventLoop>(&mut gdbstub) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => {
                info!("GDB client has disconnected. Running...");

                if let Err(e) = gdbstub.vm_request(GdbRequestPayload::SetSingleStep(false)) {
                    error!("Failed to disable single step: {:?}", e);
                }

                if let Err(e) = gdbstub.vm_request(GdbRequestPayload::SetHwBreakPoint(Vec::new())) {
                    error!("Failed to remove breakpoints: {:?}", e);
                }

                if let Err(e) = gdbstub.vm_request(GdbRequestPayload::Resume) {
                    error!("Failed to resume the VM: {:?}", e);
                }
            }
            _ => {
                error!("Target exited or terminated");
            }
        },
        Err(e) => {
            error!("error occurred in GDB session: {}", e);
        }
    }
}

// TODO: Add VcpuControl, VcpuDebugStatusMessage
pub struct GdbStub {
    gdb_sender: mpsc::Sender<GdbRequest>,
    gdb_event: vmm_sys_util::eventfd::EventFd,
    vm_event: vmm_sys_util::eventfd::EventFd,

    hw_breakpoints: Vec<vm_memory::GuestAddress>,
    single_step: bool,
}

impl GdbStub {
    pub fn new(
        gdb_sender: mpsc::Sender<GdbRequest>,
        gdb_event: vmm_sys_util::eventfd::EventFd,
        vm_event: vmm_sys_util::eventfd::EventFd,
    ) -> Self {
        Self {
            gdb_sender,
            gdb_event,
            vm_event,
            hw_breakpoints: Default::default(),
            single_step: false,
        }
    }

    fn vm_request(&self, payload: GdbRequestPayload) -> GdbResult<GdbResponsePayload> {
        let (response_sender, response_receiver) = std::sync::mpsc::channel();
        let request = GdbRequest {
            sender: response_sender,
            payload,
        };
        info!("vm_request request: {:?}", request);
        let event_value = match request.payload {
            GdbRequestPayload::ReadRegs => GdbResponseEventKind::ReadRegs,
            GdbRequestPayload::WriteRegs(_) => GdbResponseEventKind::WriteRegs,
            GdbRequestPayload::ReadMem(_, _) => GdbResponseEventKind::ReadMem,
            GdbRequestPayload::WriteMem(_, _) => GdbResponseEventKind::WriteMem,
            GdbRequestPayload::Pause => GdbResponseEventKind::Pause,
            GdbRequestPayload::Resume => GdbResponseEventKind::Resume,
            GdbRequestPayload::SetSingleStep(_) => GdbResponseEventKind::SetSingleStep,
            GdbRequestPayload::SetHwBreakPoint(_) => GdbResponseEventKind::SetHwBreakPoint,
        };
        self.gdb_sender
            .send(request)
            .map_err(|_| Error::GdbRequest)?;
        self.gdb_event
            .write(event_value as u64)
            .map_err(Error::GdbResponseNotify)?;
        //let res = response_receiver.recv_timeout(std::time::Duration::from_secs(5)).map_err(Error::VmResponseTimeout)??;
        let res = response_receiver.recv().map_err(Error::GdbResponse)??;
        info!("vm_request res: {:?}", res);
        Ok(res)
    }
}

impl Target for GdbStub {
    type Arch = GdbArch;
    type Error = &'static str;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }
}

impl SingleThreadBase for GdbStub {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        match self.vm_request(GdbRequestPayload::ReadRegs) {
            Ok(GdbResponsePayload::RegValues(r)) => {
                *regs = *r;
                Ok(())
            }
            Ok(s) => {
                error!("Unexpected response for ReadRegs: {:?}", s);
                Err(TargetError::NonFatal)
            }
            Err(e) => {
                error!("Failed to request ReadRegs: {:?}", e);
                Err(TargetError::NonFatal)
            }
        }
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        match self.vm_request(GdbRequestPayload::WriteRegs(Box::new(regs.clone()))) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to request WriteRegs: {:?}", e);
                Err(TargetError::NonFatal)
            }
        }
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<(), Self> {
        match self.vm_request(GdbRequestPayload::ReadMem(
            GuestAddress(start_addr),
            data.len(),
        )) {
            Ok(GdbResponsePayload::MemoryRegion(r)) => {
                for (dst, v) in data.iter_mut().zip(r.iter()) {
                    *dst = *v;
                }
                Ok(())
            }
            Ok(s) => {
                error!("Unexpected response for ReadMem: {:?}", s);
                Err(TargetError::NonFatal)
            }
            Err(e) => {
                error!("Failed to request ReadMem: {:?}", e);
                Err(TargetError::NonFatal)
            }
        }
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        match self.vm_request(GdbRequestPayload::WriteMem(
            GuestAddress(start_addr),
            data.to_owned(),
        )) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to request WriteMem: {:?}", e);
                Err(TargetError::NonFatal)
            }
        }
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadResume for GdbStub {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        info!("resume");
        // TODO: Add signal support
        if signal.is_some() {
            return Err("no support for continuing with signal");
        }
        match self.vm_request(GdbRequestPayload::SetSingleStep(false)) {
            Ok(_) => {
                self.single_step = false;
            }
            Err(e) => {
                error!("Failed to request SetSingleStep: {:?}", e);
                return Err("Failed to request SetSingleStep");
            }
        }
        match self.vm_request(GdbRequestPayload::Resume) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to resume the target: {:?}", e);
                return Err("Failed to resume the target");
            }
        }
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for GdbStub {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        info!("step");
        // TODO: Add signal support
        if signal.is_some() {
            return Err("no support for stepping with signal");
        }

        match self.vm_request(GdbRequestPayload::SetSingleStep(true)) {
            Ok(_) => {
                self.single_step = true;
            }
            Err(e) => {
                error!("Failed to request SetSingleStep: {:?}", e);
                return Err("Failed to request SetSingleStep");
            }
        }
        match self.vm_request(GdbRequestPayload::Resume) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to resume the target: {:?}", e);
                return Err("Failed to resume the target");
            }
        }
    }
}

impl Breakpoints for GdbStub {
    #[inline(always)]
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }
}

impl HwBreakpoint for GdbStub {
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        // If we already have 4 breakpoints, we cannot set a new one.
        if self.hw_breakpoints.len() >= 4 {
            error!("Not allowed to set more than 4 HW breakpoints");
            return Err(TargetError::NonFatal);
        }

        self.hw_breakpoints.push(GuestAddress(addr));

        let payload = GdbRequestPayload::SetHwBreakPoint(self.hw_breakpoints.clone());
        match self.vm_request(payload) {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("Failed to request SetHwBreakPoint: {:?}", e);
                Err(TargetError::NonFatal)
            }
        }
    }
    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        self.hw_breakpoints.retain(|&b| b.0 != addr);

        let payload = GdbRequestPayload::SetHwBreakPoint(self.hw_breakpoints.clone());
        match self.vm_request(payload) {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("Failed to request SetHwBreakPoint: {:?}", e);
                Err(TargetError::NonFatal)
            }
        }
    }
}

enum GdbEventLoop {}

impl run_blocking::BlockingEventLoop for GdbEventLoop {
    type Target = GdbStub;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<ArchUsize>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        // Polling
        loop {
            // This read is non-blocking.
            match target.vm_event.read() {
                Ok(v) => {
                    if v == 256 {
                        info!("Received VmExit::Debug");
                        target.vm_request(GdbRequestPayload::Pause).map_err(|_| {
                            run_blocking::WaitForStopReasonError::Target("Failed to pause VM")
                        })?;
                        let stop_reason = if target.single_step {
                            SingleThreadStopReason::DoneStep
                        } else {
                            SingleThreadStopReason::HwBreak(())
                        };
                        return Ok(run_blocking::Event::TargetStopped(stop_reason));
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        return Err(run_blocking::WaitForStopReasonError::Connection(e));
                    }
                }
            }

            if conn.peek().map(|b| b.is_some()).unwrap_or(true) {
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;
                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        target.vm_request(GdbRequestPayload::Pause).map_err(|e| {
            error!("Failed to pause the target: {:?}", e);
            "Failed to pause the target"
        })?;
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

if {[catch {

# define run engine funtion
source [file join {/home/anonymousvikram/.lscc} scripts tcl flow run_engine.tcl]
# define global variables
global para
set para(gui_mode) "1"
set para(prj_dir) "/home/anonymousvikram/workspace/e155/work/lab7/fpga/radiant/lab7proj"
# synthesize IPs
# synthesize VMs
# synthesize top design
file delete -force -- lab7proj_impl_1.vm lab7proj_impl_1.ldc
::radiant::runengine::run_engine_newmsg synthesis -f "lab7proj_impl_1_lattice.synproj" -logfile "lab7proj_impl_1_lattice.srp"
::radiant::runengine::run_postsyn [list -a iCE40UP -p iCE40UP5K -t SG48 -sp High-Performance_1.2V -oc Industrial -top -w -o lab7proj_impl_1_syn.udb lab7proj_impl_1.vm] [list /home/anonymousvikram/workspace/e155/work/lab7/fpga/radiant/lab7proj/impl_1/lab7proj_impl_1.ldc]

} out]} {
   ::radiant::runengine::runtime_log $out
   exit 1
}

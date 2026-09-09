//go:build !secops_planted_fault

package secops

// plantedFault is the seam the evaluation's negative control uses, and in
// every ordinary build it is this: nothing.
//
// A detection suite that has never failed has not been shown to be able to
// fail. So scripts/run-security-ops-eval.sh builds the replay harness a
// second time with -tags secops_planted_fault, which selects the other
// variant of this function (fault_on.go) and breaks exactly one correlation
// edge. The harness must then report an incomplete incident and exit
// non-zero; if it still passes, the linkage check is decorative and the whole
// result is worthless.
//
// The fault cannot leak into a normal binary: it exists only in a file
// guarded by that build tag, and the tag is set nowhere but in that one
// command in the eval script.
func plantedFault(*Event) {}

// PlantedFaultActive is false in every build that is not the negative
// control. The harness prints it, so a result can never be mistaken for the
// other kind of run.
const PlantedFaultActive = false

package domain

type BpfMetrics struct {
	Passed   uint64
	Dropped  uint64
	NXDomain uint64
}

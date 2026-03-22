package repository

type BpfConfigRepositoryIface interface {
	UpdateThreshold(threshold uint32) error
}

type BpfMetricsRepositoryIface interface {
	GetMetrics() (passed uint64, dropped uint64, err error)
}

type DNSMonitorRepository struct {
	Conf    BpfConfigRepositoryIface
	Metrics BpfMetricsRepositoryIface // Добавили поле
}

func NewDNSMonitorRepository(
	c BpfConfigRepositoryIface,
	m BpfMetricsRepositoryIface, // Обновили конструктор
) *DNSMonitorRepository {
	return &DNSMonitorRepository{
		Conf:    c,
		Metrics: m,
	}
}

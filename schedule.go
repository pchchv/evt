package evt

import "time"

// Represents a job schedule
type schedule struct {
	stopCh     chan struct{} // Stop channel to control job
	handFunc   interface{}   // Schedule the handling function
	funcParams []interface{} // Params of function
	ticker     *time.Ticker  // Period specified by a duration
	running    bool          // Indicates the current running state of schedule
}

// newSchedule returns a new schedule instance
func newSchedule(period time.Duration, handFunc interface{}, params ...interface{}) *schedule {
	return &schedule{
		stopCh:     make(chan struct{}),
		handFunc:   handFunc,
		funcParams: params,
		ticker:     time.NewTicker(period),
	}
}

// Start triggers the schedule job
func (s *schedule) start() {
	if s.running {
		return
	}
	s.running = true
	go func() {
		for {
			select {
			case <-s.ticker.C:
				callJobFuncWithParams(s.handFunc, s.funcParams)
			case <-s.stopCh:
				s.ticker.Stop()
				return
			}
		}
	}()
}

// Stop previously started schedule job
func (s *schedule) stop() {
	if !s.running {
		return
	}
	s.running = false
	s.stopCh <- struct{}{}
}

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

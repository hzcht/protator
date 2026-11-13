package proxy

import "testing"

// The export defaults are filled unconditionally (the service is opt-in via
// enabled, but a later enabled=true must not boot with zero/empty knobs), and
// explicit values must survive the fill.
func TestExportDefaults(t *testing.T) {
	// SelfIPURLs satisfies the one hard validation that would otherwise abort
	// fillDefaults before its tail; nothing else in a bare config errors.
	c := Config{Checker: CheckerConfig{SelfIPURLs: []string{"http://self.ip"}}}
	if err := c.fillDefaults(); err != nil {
		t.Fatalf("fillDefaults: %v", err)
	}
	if c.Export.Listen != "127.0.0.1:8899" || c.Export.RefreshMinutes != 5 || c.Export.ListSize != 1000 {
		t.Fatalf("export defaults wrong: %+v", c.Export)
	}

	c2 := Config{
		Checker: CheckerConfig{SelfIPURLs: []string{"http://self.ip"}},
		Export:  ExportConfig{Enabled: true, Listen: "0.0.0.0:9", RefreshMinutes: 30, ListSize: 2000},
	}
	if err := c2.fillDefaults(); err != nil {
		t.Fatalf("fillDefaults: %v", err)
	}
	if c2.Export.Listen != "0.0.0.0:9" || c2.Export.RefreshMinutes != 30 || c2.Export.ListSize != 2000 {
		t.Fatalf("explicit export values were overwritten: %+v", c2.Export)
	}
}

// Copyright (C) 2021-2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"perfspect/internal/cpus"
)

// Without fixed TMA counters (e.g. a generic_arch guest), level-1 TMA must come from the
// GP-counter alternate file, and no fixed-counter TMA event may reach perf.
func TestAlternateTMAWithoutFixedCounters(t *testing.T) {
	for _, uarch := range []string{cpus.UarchICX, cpus.UarchSPR, cpus.UarchEMR, cpus.UarchGNR, cpus.UarchDMR} {
		t.Run(uarch, func(t *testing.T) {
			md := Metadata{}
			md.Microarchitecture = uarch
			md.Vendor = "GenuineIntel"
			md.NumGeneralPurposeCounters = 8
			md.SupportsInstructions, md.SupportsFixedCycles, md.SupportsFixedInstructions = true, true, true
			md.SocketCount, md.CoresPerSocket, md.ThreadsPerCore = 1, 4, 1
			loader, err := NewLoader(md.Microarchitecture, false)
			require.NoError(t, err)
			metrics, groups, err := loader.Load(LoaderConfig{Metadata: md})
			require.NoError(t, err)

			names := make(map[string]bool)
			for _, m := range metrics {
				names[m.Name] = true
			}
			for _, want := range []string{"Frontend_Bound", "Fetch_Latency", "Fetch_Bandwidth", "Bad_Speculation", "Backend_Bound", "Memory_Bound", "Core_Bound", "Retiring", "Heavy_Operations"} {
				assert.True(t, names[want], "missing %s", want)
			}
			for _, g := range groups {
				for _, e := range g {
					assert.False(t, strings.HasPrefix(e.Raw, "topdown") || strings.Contains(e.Raw, "perf_metrics"), e.Raw)
				}
			}
		})
	}
}

func TestMetricsAndGroupsOverride(t *testing.T) {
	input := func() ([]MetricDefinition, []GroupDefinition) {
		return []MetricDefinition{{Expression: "[topdown-retiring] / [topdown.slots]"}},
			[]GroupDefinition{{{Raw: "topdown.slots"}, {Raw: "topdown-retiring"}}}
	}
	defs, groups := input()
	defs, groups = metricsAndGroupsOverride(cpus.UarchDMR, defs, groups)
	assert.Equal(t, "[topdown-retiring] / [slots]", defs[0].Expression)
	assert.Equal(t, "slots", groups[0][0].Raw)

	defs, groups = input()
	defs, groups = metricsAndGroupsOverride(cpus.UarchGNR, defs, groups)
	assert.Equal(t, "[topdown-retiring] / [topdown.slots]", defs[0].Expression)
	assert.Equal(t, "topdown.slots", groups[0][0].Raw)
}

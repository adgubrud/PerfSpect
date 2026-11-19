// Copyright (C) 2021-2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"slices"
	"strings"
	"testing"

	"perfspect/internal/cpus"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCPUPMUFormat(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   cpuPMUFormat
	}{
		{
			// The guest that failed: kernel fell back to the architectural PMU.
			name:   "generic_arch_v5+ guest, 8-bit umask, no response MSR term",
			stdout: "pmu_name=generic_arch_v5+\nformat.event=config:0-7\nformat.umask=config:8-15\nformat.edge=config:18\nformat.inv=config:23\nformat.cmask=config:24-31\n",
			want:   cpuPMUFormat{pmuName: "generic_arch_v5+", umaskMax: 0xff, fields: []string{"event", "umask", "edge", "inv", "cmask"}},
		},
		{
			// Real sysfs output from a Skylake-SP host; pre-DMR Intel servers share these fields.
			name:   "pre-DMR Intel server, 8-bit umask and offcore_rsp",
			stdout: "pmu_name=skylake\nformat.any=config:21\nformat.cmask=config:24-31\nformat.edge=config:18\nformat.event=config:0-7\nformat.frontend=config1:0-23\nformat.in_tx=config:32\nformat.in_tx_cp=config:33\nformat.inv=config:23\nformat.ldlat=config1:0-15\nformat.offcore_rsp=config1:0-63\nformat.pc=config:19\nformat.umask=config:8-15\n",
			want:   cpuPMUFormat{pmuName: "skylake", umaskMax: 0xff, offcoreTerm: "offcore_rsp", fields: preDMRFormatFields},
		},
		{
			name:   "DMR on v7.0-v7.2, extended umask and offcore_rsp",
			stdout: "pmu_name=panthercove\nformat.event=config:0-7\nformat.umask=config:8-15,40-47\nformat.offcore_rsp=config1:0-63\n",
			want:   cpuPMUFormat{pmuName: "panthercove", umaskMax: 0xffff, offcoreTerm: "offcore_rsp", fields: []string{"event", "umask", "offcore_rsp"}},
		},
		{
			name:   "DMR on v7.3+, offcore_rsp renamed to offmodule_rsp",
			stdout: "pmu_name=panthercove\nformat.umask=config:8-15,40-47\nformat.offmodule_rsp=config1:0-63\n",
			want:   cpuPMUFormat{pmuName: "panthercove", umaskMax: 0xffff, offcoreTerm: "offmodule_rsp", fields: []string{"umask", "offmodule_rsp"}},
		},
		{
			// Script output missing entirely, e.g. no cpu PMU in sysfs.
			name:   "nothing exposed",
			stdout: "pmu_name=\n",
			want:   cpuPMUFormat{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCPUPMUFormat(tt.stdout)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCPUPMUFormatRejectsBadUmaskSpec(t *testing.T) {
	for _, spec := range []string{"config8-15", "config:15-8", "config:a-b", "config:0-63,64-70"} {
		_, err := parseCPUPMUFormat("format.umask=" + spec + "\n")
		assert.Error(t, err, spec)
	}
}

func TestCoreEventIsCollectableUmaskWidth(t *testing.T) {
	// MEM_LOAD_RETIRED.L2_MISS as the DMR event file encodes it: umask 0x00 + UMaskExt 0x80.
	l2Miss := CoreEvent{EventName: "MEM_LOAD_RETIRED.L2_MISS", EventCode: "0xd1", UMask: "0x00", UMaskExt: "0x80"}
	narrow := CoreEvent{EventName: "MEM_LOAD_RETIRED.L1_MISS", EventCode: "0xd1", UMask: "0x08"}
	modifier := CoreEvent{EventName: "EVENT:u0x1e:c1", EventCode: "0xa3", UMask: "0x04"}

	tests := []struct {
		name     string
		umaskMax uint64
		event    CoreEvent
		want     bool
	}{
		{"8-bit format rejects extended umask", 0xff, l2Miss, false},
		{"16-bit format accepts extended umask", 0xffff, l2Miss, true},
		{"unknown format does not filter", 0, l2Miss, true},
		{"8-bit format accepts 8-bit umask", 0xff, narrow, true},
		{"umask from name modifier is checked", 0xf, modifier, false},
		{"unparseable UMaskExt is rejected", 0xffff, CoreEvent{EventName: "BAD.EXT", EventCode: "0xd1", UMask: "0x00", UMaskExt: "0x100"}, false},
		{"unparseable UMaskExt is rejected with unknown format", 0, CoreEvent{EventName: "BAD.EXT", EventCode: "0xd1", UMask: "0x00", UMaskExt: "zz"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := Metadata{X86Metadata: X86Metadata{UMaskMax: tt.umaskMax, SupportsOCR: true, SupportsRefCycles: true, SupportsPEBS: true, SupportsFixedTMA: true}}
			assert.Equal(t, tt.want, tt.event.IsCollectable(md))
		})
	}
}

func TestCoreEventStringForPerfResponseMSRTerm(t *testing.T) {
	event := CoreEvent{EventName: "OMR.READS_TO_CORE.ANY_RESPONSE", EventCode: "0x2a", UMask: "0x01,0x02,0x04,0x08", Offmodule: "1", MSRValue: "0x4000000000004477"}
	for _, tt := range []struct{ term, want string }{
		{"", "offcore_rsp=0x4000000000004477"}, // default when the format was not read
		{"offmodule_rsp", "offmodule_rsp=0x4000000000004477"},
	} {
		event.responseMSRTerm = tt.term
		got, err := event.StringForPerf()
		require.NoError(t, err)
		assert.True(t, strings.Contains(got, tt.want), got)
		assert.True(t, strings.Contains(got, "umask=0x01,"), got)
	}
}

func TestCoreEventIsCollectableFormatTerms(t *testing.T) {
	guestFields := []string{"event", "umask", "edge", "inv", "cmask"} // generic_arch_v5+, no eq
	dmrFields := append(slices.Clone(guestFields), "eq", "offmodule_rsp")
	eqEvent := CoreEvent{EventName: "EXAMPLE.EQ:eq1", EventCode: "0xa3", UMask: "0x04", CounterMask: "4"}
	cmaskEvent := CoreEvent{EventName: "EXAMPLE.CMASK:c4", EventCode: "0xa3", UMask: "0x04", SampleAfterValue: "100003"}
	omrEvent := CoreEvent{EventName: "OMR.READS_TO_CORE.ANY_RESPONSE", EventCode: "0x2a", UMask: "0x01", Offmodule: "1", MSRValue: "0x1", responseMSRTerm: "offmodule_rsp"}
	fixedEvent := CoreEvent{EventName: "INST_RETIRED.ANY", EventCode: "0x00", UMask: "0x01"}

	tests := []struct {
		name   string
		fields []string
		event  CoreEvent
		want   bool
	}{
		{"guest rejects eq", guestFields, eqEvent, false},
		{"DMR kernel accepts eq", dmrFields, eqEvent, true},
		{"unknown format does not filter", nil, eqEvent, true},
		{"guest accepts cmask and period", guestFields, cmaskEvent, true},
		{"guest rejects response MSR term", guestFields, omrEvent, false},
		{"DMR kernel accepts response MSR term", dmrFields, omrEvent, true},
		{"perf named events are not checked", guestFields[:1], fixedEvent, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := Metadata{X86Metadata: X86Metadata{PMUFormatFields: tt.fields, SupportsOCR: true, SupportsRefCycles: true, SupportsPEBS: true, SupportsFixedTMA: true}}
			assert.Equal(t, tt.want, tt.event.IsCollectable(md))
		})
	}
}

// Events are looked up by base name; the check must still see the metric's modifiers.
func TestGetUncollectableEventsChecksModifiers(t *testing.T) {
	coreEvents := CoreEvents{Events: []CoreEvent{{EventName: "IDQ.MITE_UOPS", EventCode: "0x79", UMask: "0x04"}}}
	md := Metadata{X86Metadata: X86Metadata{PMUFormatFields: []string{"event", "umask", "edge", "inv", "cmask"}}}
	assert.Equal(t, []string{"IDQ.MITE_UOPS:c10:i1:eq1"},
		getUncollectableEvents([]string{"IDQ.MITE_UOPS:c10:i1:eq1"}, coreEvents, UncoreEvents{}, OtherEvents{}, md))
	assert.Empty(t, getUncollectableEvents([]string{"IDQ.MITE_UOPS:c10:i1"}, coreEvents, UncoreEvents{}, OtherEvents{}, md))
}

func TestGetMetadataScriptsUarchOverrides(t *testing.T) {
	templates := func(uarch string) map[string]string {
		scripts, err := getMetadataScripts(false, true, 8, false, uarch)
		require.NoError(t, err)
		m := make(map[string]string)
		for _, s := range scripts {
			m[s.Name] = s.ScriptTemplate
		}
		return m
	}
	dmr, gnr := templates(cpus.UarchDMR), templates(cpus.UarchGNR)
	for name, want := range uarchScriptOverrides[cpus.UarchDMR] {
		assert.Equal(t, want, dmr[name], name)
		assert.NotEqual(t, want, gnr[name], name)
	}
	assert.Equal(t, gnr[scriptKernelVersion], dmr[scriptKernelVersion], "non-overridden scripts are unchanged")
}

// preDMRFormatFields is the cpu PMU format of a pre-DMR Intel server, in sysfs order.
var preDMRFormatFields = []string{"any", "cmask", "edge", "event", "frontend", "in_tx", "in_tx_cp", "inv", "ldlat", "offcore_rsp", "pc", "umask"}

// The PMU format filters must not drop any metric or event on uarchs that worked before them.
func TestPMUFormatFilterIsNoOpOnExistingUarchs(t *testing.T) {
	// Evaluable holds compiled expressions that never compare equal, so compare the source fields.
	load := func(t *testing.T, uarch string, withFormat bool) ([]string, []GroupDefinition) {
		md := Metadata{}
		md.Microarchitecture, md.Vendor, md.NumGeneralPurposeCounters = uarch, "GenuineIntel", 8
		md.SupportsInstructions, md.SupportsFixedCycles, md.SupportsFixedInstructions = true, true, true
		md.SupportsFixedTMA, md.SupportsOCR, md.SupportsPEBS, md.SupportsRefCycles = true, true, true, true
		md.SocketCount, md.CoresPerSocket, md.ThreadsPerCore = 1, 4, 1
		if withFormat {
			md.PMUFormatFields, md.UMaskMax, md.OffcoreResponseTerm = preDMRFormatFields, 0xff, "offcore_rsp"
		}
		loader, err := NewLoader(uarch, false)
		require.NoError(t, err)
		metrics, groups, err := loader.Load(LoaderConfig{Metadata: md})
		require.NoError(t, err)
		var summary []string
		for _, m := range metrics {
			summary = append(summary, m.Name+" = "+m.Expression+" ; "+m.ThresholdExpression)
		}
		return summary, groups
	}
	for _, uarch := range []string{cpus.UarchICX, cpus.UarchSPR, cpus.UarchEMR, cpus.UarchGNR, cpus.UarchSRF, cpus.UarchCWF} {
		t.Run(uarch, func(t *testing.T) {
			wantMetrics, wantGroups := load(t, uarch, false)
			gotMetrics, gotGroups := load(t, uarch, true)
			require.NotEmpty(t, wantMetrics)
			assert.Equal(t, wantMetrics, gotMetrics)
			assert.Equal(t, wantGroups, gotGroups)
		})
	}
}

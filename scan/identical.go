package scan

/*
   AIMS (Attacked Infrastructure Modular Specification)
   Copyright (C) 2021 Maxime Landon

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
import (
	"fmt"

	scan "github.com/d3c3ptive/aims/scan/pb"
)

// AreScansIdentical reports whether two runs are the same scan re-imported.
//
// RawXML is the scanner's verbatim output and thus a definitive fingerprint: when both runs carry
// it, equality alone decides identity and inequality alone rules it out. Only when a run lacks raw
// output does it fall back to a field-weighted comparison over the runs' identity fields.
//
// The fallback counts *evidence*, not absence: a field contributes only when both runs actually
// populated it — agreement is positive evidence, a disagreement on a populated field is
// disqualifying, and a field left empty on either side is neutral. Two dataless runs therefore score
// no evidence and are not "identical" (the earlier scoring treated two empty task-lists as a match,
// which made every empty run collide with every other). Runs match when they agree on every
// populated identity field, disagree on none, and carry at least one field of real evidence.
func AreScansIdentical(a, b *scan.RunORM) bool {
	if a == nil || b == nil {
		return false
	}

	// RawXML is decisive when both runs have it.
	if a.RawXML != "" && b.RawXML != "" {
		return a.RawXML == b.RawXML
	}

	var ev evidence
	ev.str(a.Args, b.Args)
	ev.str(a.Scanner, b.Scanner)
	ev.str(a.StartStr, b.StartStr)
	ev.str(a.SessionId, b.SessionId)
	ev.str(a.ProfileName, b.ProfileName)
	ev.str(a.Version, b.Version)
	ev.num(a.Start, b.Start)

	// Task lists count only when at least one run has them — a shared empty list is not evidence.
	ev.list(len(a.Begin) > 0 || len(b.Begin) > 0, compareScanTasks(a.Begin, b.Begin))
	ev.list(len(a.End) > 0 || len(b.End) > 0, compareScanTasks(a.End, b.End))
	ev.list(len(a.Progress) > 0 || len(b.Progress) > 0, compareTaskProgresses(a.Progress, b.Progress))

	return ev.identical()
}

// evidence accumulates a same-scan judgement over the runs' identity fields: how many populated
// fields agreed, and whether any populated field disagreed. Only fields both runs set are weighed;
// shared absence is never counted.
type evidence struct {
	agree    int
	conflict bool
}

// str weighs a string field: neutral if either side is empty, otherwise agreement or conflict.
func (e *evidence) str(a, b string) {
	if a == "" || b == "" {
		return
	}
	if a == b {
		e.agree++
	} else {
		e.conflict = true
	}
}

// num weighs an integer field, treating zero as "unset" (hence neutral).
func (e *evidence) num(a, b int64) {
	if a == 0 || b == 0 {
		return
	}
	if a == b {
		e.agree++
	} else {
		e.conflict = true
	}
}

// list weighs a collection comparison, but only when the collection is actually present on a run.
func (e *evidence) list(present, equal bool) {
	if !present {
		return
	}
	if equal {
		e.agree++
	} else {
		e.conflict = true
	}
}

// identical holds when the runs agreed on at least one populated field and disagreed on none.
func (e *evidence) identical() bool {
	return e.agree > 0 && !e.conflict
}

// compareScanTasks compares two lists of ScanTaskORM objects for equality without considering IDs.
func compareScanTasks(a, b []*scan.ScanTaskORM) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps to track the presence of tasks
	taskMapA := make(map[string][]*scan.ScanTaskORM)
	taskMapB := make(map[string][]*scan.ScanTaskORM)

	// Populate maps with tasks from both lists, using a composite key based on non-ID fields
	for _, task := range a {
		if task != nil {
			key := generateTaskKey(task)
			taskMapA[key] = append(taskMapA[key], task)
		}
	}
	for _, task := range b {
		if task != nil {
			key := generateTaskKey(task)
			taskMapB[key] = append(taskMapB[key], task)
		}
	}

	// Check if both maps have the same tasks
	if len(taskMapA) != len(taskMapB) {
		return false
	}

	for key, tasksA := range taskMapA {
		tasksB, exists := taskMapB[key]
		if !exists || len(tasksA) != len(tasksB) {
			return false
		}
		// Compare individual tasks in the lists
		for i, taskA := range tasksA {
			if !compareScanTaskORMs(taskA, tasksB[i]) {
				return false
			}
		}
	}

	return true
}

// compareTaskProgresses compares two lists of TaskProgressORM objects for equality without considering IDs.
func compareTaskProgresses(a, b []*scan.TaskProgressORM) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps to track the presence of tasks
	taskMapA := make(map[string][]*scan.TaskProgressORM)
	taskMapB := make(map[string][]*scan.TaskProgressORM)

	// Populate maps with tasks from both lists, using a composite key based on non-ID fields
	for _, task := range a {
		if task != nil {
			key := generateTaskProgressKey(task)
			taskMapA[key] = append(taskMapA[key], task)
		}
	}
	for _, task := range b {
		if task != nil {
			key := generateTaskProgressKey(task)
			taskMapB[key] = append(taskMapB[key], task)
		}
	}

	// Check if both maps have the same tasks
	if len(taskMapA) != len(taskMapB) {
		return false
	}

	for key, tasksA := range taskMapA {
		tasksB, exists := taskMapB[key]
		if !exists || len(tasksA) != len(tasksB) {
			return false
		}
		// Compare individual tasks in the lists
		for i, taskA := range tasksA {
			if !compareTaskProgressORMs(taskA, tasksB[i]) {
				return false
			}
		}
	}

	return true
}

// compareTaskProgressORMs compares two TaskProgressORM objects for equality based on non-ID fields.
func compareTaskProgressORMs(a, b *scan.TaskProgressORM) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.Etc == b.Etc &&
		a.Percent == b.Percent &&
		a.Remaining == b.Remaining &&
		a.Task == b.Task &&
		a.Time == b.Time
}

// generateTaskProgressKey generates a unique key for a TaskProgressORM based on non-ID fields.
func generateTaskProgressKey(task *scan.TaskProgressORM) string {
	return fmt.Sprintf("%d|%g|%d|%s|%d", task.Etc, task.Percent, task.Remaining, task.Task, task.Time)
}

// compareScanTaskORMs compares two ScanTaskORM objects for equality based on non-ID fields.
func compareScanTaskORMs(a, b *scan.ScanTaskORM) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.ExtraInfo == b.ExtraInfo &&
		a.Task == b.Task &&
		a.Time == b.Time
}

// generateTaskKey generates a unique key for a ScanTaskORM based on non-ID fields.
func generateTaskKey(task *scan.ScanTaskORM) string {
	return fmt.Sprintf("%s|%s|%d", task.ExtraInfo, task.Task, task.Time)
}

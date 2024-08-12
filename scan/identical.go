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

	"github.com/maxlandon/aims/internal/util"
	"github.com/maxlandon/aims/proto/scan"
	scanpb "github.com/maxlandon/aims/proto/scan"
	"github.com/maxlandon/aims/proto/scan/nmap"
)

// AreScansIdentical compares two scanpb.ScanORM objects to determine if they represent the same host.
func AreScansIdentical(a, b *scanpb.RunORM) bool {
	if a == nil || b == nil {
		return false
	}

	weightBy := util.WeightedCompare
	intCmp := util.CompareInts
	strCmp := util.CompareStrings

	// Define weights for each field
	totalScore := 0
	maxScore := 20 * 10 // Example max score (20 fields with a weight of 10 each)

	// Unambiguous fields
	totalScore += weightBy(strCmp(a.RawXML, b.RawXML), 200)
	totalScore += weightBy(compareScanTasks(a.Begin, b.Begin), 50)
	totalScore += weightBy(compareScanTasks(a.End, b.End), 50)
	totalScore += weightBy(compareTaskProgresses(a.Progress, b.Progress), 50) // List of TaskProgressORM

	// Strong fields
	totalScore += weightBy(intCmp(a.Start, b.Start), 20)
	totalScore += weightBy(strCmp(a.StartStr, b.StartStr), 20)
	totalScore += weightBy(strCmp(a.SessionId, b.SessionId), 20)

	// Weak fields
	totalScore += weightBy(strCmp(a.Args, b.Args), 5)
	totalScore += weightBy(strCmp(a.Scanner, b.Scanner), 5)
	totalScore += weightBy(strCmp(a.ProfileName, b.ProfileName), 5)
	// totalScore += weightedCompare(a.PostScripts, b.PostScripts, 10) // List of ScriptORM
	// totalScore += weightedCompare(a.PreScripts, b.PreScripts, 10)   // List of ScriptORM
	// totalScore += weightedCompare(a.Results, b.Results, 10)         // List of ResultORM
	// totalScore += weightedCompare(a.Targets, b.Targets, 10)         // List of TargetORM
	// totalScore += weightedCompare(a.Stats, b.Stats, 10)             // StatsORM
	// totalScore += weightedCompare(a.Verbose, b.Verbose, 10)         // VerboseORM
	totalScore += weightBy(strCmp(a.Version, b.Version), 5)

	// Return true if total score meets or exceeds the threshold
	return totalScore >= (maxScore / 2)
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
	return string(task.Etc) + "|" + fmt.Sprintf("%d", task.Percent) + "|" + string(task.Remaining) + "|" + task.Task + "|" + string(task.Time)
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
	return task.ExtraInfo + "|" + task.Task + "|" + string(task.Time)
}

// compareScriptORMs compares two slices of ScriptORM for equality.
func compareScriptORMs(a, b []*nmap.ScriptORM) bool {
	if len(a) != len(b) {
		return false
	}

	seen := make(map[string]bool)
	for _, scriptA := range a {
		for _, scriptB := range b {
			if scriptA.Id == scriptB.Id && scriptA.Name == scriptB.Name && scriptA.Output == scriptB.Output {
				seen[scriptA.Id] = true
				break
			}
		}
	}

	return len(seen) == len(a)
}

// compareFinishedORMs compares two FinishedORM objects for equality using relevant fields.
func compareFinishedORMs(a, b *scanpb.FinishedORM) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.Elapsed == b.Elapsed &&
		a.ErrorMsg == b.ErrorMsg &&
		a.Exit == b.Exit &&
		a.StatsId == b.StatsId &&
		a.Summary == b.Summary &&
		a.Time == b.Time &&
		a.TimeStr == b.TimeStr
}

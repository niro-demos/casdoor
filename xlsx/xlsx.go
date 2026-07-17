// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xlsx

import (
	"fmt"

	"github.com/tealeg/xlsx"
)

// ReadXlsxFile parses the xlsx file at path into a slice of string rows. It
// never panics: a malformed or non-zip file (e.g. a plain CSV renamed to
// .xlsx) is reported as a normal error so HTTP handlers can return a clean
// 4xx/5xx response instead of letting a panic reach the framework's default
// (potentially debug-mode) error handler. The recover also guards against
// any other panic surfaced by the third-party xlsx library while reading
// sheets/rows/cells.
func ReadXlsxFile(path string) (res [][]string, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("invalid xlsx file: %v", r)
		}
	}()

	file, err := xlsx.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("invalid xlsx file: %w", err)
	}

	res = [][]string{}
	for _, sheet := range file.Sheets {
		for _, row := range sheet.Rows {
			line := []string{}
			for _, cell := range row.Cells {
				text := cell.String()
				line = append(line, text)
			}
			res = append(res, line)
		}
		break
	}

	return res, nil
}

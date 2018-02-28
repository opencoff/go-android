// pkg_test.go -- Test harness for android/pkg
//
// (c) 2016 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package pkg_test

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	// module under test
	"android/pkg"
)

func assert(cond bool, t *testing.T, msg string) {

	if cond {
		return
	}

	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}

	t.Fatalf("%s: %d: Assertion failed: %q\n", file, line, msg)
}

func Test0(t *testing.T) {
	pkg, err := pkg.OpenPackageDB("./packages.xml", "./packages.list")
	assert(err == nil, t, fmt.Sprintf("%s", err))

	uid := uint32(os.Getuid())
	pv := pkg.GetListByUid(uid)
	assert(pv != nil, t, fmt.Sprintf("can't find uid %v", uid))
	assert(len(pv) == 1, t, fmt.Sprintf("more than one pkg with uid %v", uid))
}

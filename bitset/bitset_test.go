package bitset

import "testing"

func TestSetTestClear(t *testing.T) {
	b := New()

	if b.Test(5) {
		t.Fatal("new bitset should have no bits set")
	}

	b.Set(5)
	if !b.Test(5) {
		t.Fatal("bit 5 should be set")
	}

	b.Clear(5)
	if b.Test(5) {
		t.Fatal("bit 5 should be cleared")
	}
}

func TestCrossWordBoundaries(t *testing.T) {
	b := New()
	indices := []uint{0, 63, 64, 65, 127, 128, 1000}
	for _, i := range indices {
		b.Set(i)
	}
	for _, i := range indices {
		if !b.Test(i) {
			t.Errorf("bit %d should be set after grow", i)
		}
	}
	// A neighbour that was never set must be unset.
	if b.Test(66) {
		t.Error("bit 66 should be unset")
	}
}

func TestTestOutOfRangeIsFalse(t *testing.T) {
	b := New()
	b.Set(1)
	if b.Test(1_000_000) {
		t.Error("out-of-range Test must return false, not panic")
	}
}

func TestClearOutOfRangeIsNoop(t *testing.T) {
	b := New()
	b.Clear(1_000_000) // must not panic or allocate
	if b.Count() != 0 {
		t.Error("clearing an unset out-of-range bit must not set anything")
	}
}

func TestOr(t *testing.T) {
	a := New()
	a.Set(1)
	a.Set(130) // forces a to be wider

	b := New()
	b.Set(2)
	b.Set(64)

	a.Or(b)

	for _, want := range []uint{1, 2, 64, 130} {
		if !a.Test(want) {
			t.Errorf("after Or, bit %d should be set", want)
		}
	}
	if a.Count() != 4 {
		t.Errorf("Count = %d, want 4", a.Count())
	}
}

func TestOrGrowsReceiver(t *testing.T) {
	a := New()
	a.Set(0)
	b := New()
	b.Set(500) // b is wider than a

	a.Or(b)

	if !a.Test(500) {
		t.Error("Or must grow the receiver to absorb wider operand")
	}
}

func TestCount(t *testing.T) {
	b := New()
	if b.Count() != 0 {
		t.Errorf("empty Count = %d, want 0", b.Count())
	}
	for _, i := range []uint{1, 1, 2, 200} { // duplicate 1 should not double-count
		b.Set(i)
	}
	if b.Count() != 3 {
		t.Errorf("Count = %d, want 3", b.Count())
	}
}

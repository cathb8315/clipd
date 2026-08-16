//go:build !darwin

package clipboard

// New reports that this platform has no clipboard backend.
//
// clipd v1 receives on macOS only; on Linux the binary is a client and never
// needs to write a clipboard. Failing here — rather than silently accepting
// and discarding a copy — makes a misconfigured `clipd serve` obvious.
func New() (Clipboard, error) {
	return nil, ErrUnsupported
}

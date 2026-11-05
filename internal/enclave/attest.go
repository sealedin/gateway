package enclave

import (
	"errors"
	"io/fs"
	"os"
)

// evidence is one quote fetch: the DCAP quote plus the boot event log a verifier replays into RTMR3.
type evidence struct {
	quote    []byte
	eventLog []byte
}

// dstackSocket is the dstack guest agent's Unix socket, mounted into the container by the measured compose.
const dstackSocket = "/var/run/dstack.sock"

func fetchEvidence(reportData [ReportDataSize]byte) (evidence, error) {
	return fetchEvidenceFrom(dstackSocket, reportData)
}

// statSocket: a missing socket is dev mode (ErrNotAttested); any other failure is hard: never attested-but-degraded.
func statSocket(socket string) error {
	if _, err := os.Stat(socket); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotAttested
		}
		return err
	}
	return nil
}

func fetchEvidenceFrom(socket string, reportData [ReportDataSize]byte) (evidence, error) {
	if err := statSocket(socket); err != nil {
		return evidence{}, err
	}
	return fetchEvidenceDstack(socket, reportData)
}

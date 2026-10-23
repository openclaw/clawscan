package runner

import (
	"errors"
	"path"
	"strings"
)

func validateArtifactInspectionReceiptV2(inspection map[string]any, requiredFile string) error {
	if len(inspection) != 6 {
		return errors.New("Judge artifact inspection v2 receipt fields were invalid.")
	}
	file, ok := inspection["required_file"].(string)
	if !ok || file != requiredFile {
		return errors.New("Judge artifact inspection required_file did not match the required artifact file.")
	}
	additional, ok := inspection["additional_files_inspected"].([]any)
	if !ok {
		return errors.New("Judge artifact inspection v2 additional_files_inspected was not an array.")
	}
	for _, value := range additional {
		file, ok := value.(string)
		if !ok || !strings.HasPrefix(file, "artifact/") || file == "artifact/" || path.Clean(file) != file {
			return errors.New("Judge artifact inspection v2 additional_files_inspected contained an invalid artifact path.")
		}
	}
	return nil
}

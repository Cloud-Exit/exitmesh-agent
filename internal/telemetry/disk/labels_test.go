package disk

import (
	"strconv"

	"github.com/prometheus/prometheus/model/labels"
)

func labelsFor(i int) labels.Labels {
	return labels.FromStrings("__name__", "series", "i", strconv.Itoa(i))
}

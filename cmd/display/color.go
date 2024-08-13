package display

func colorDetailFieldName(n string) (d string) {
	return Fmt(Bg+"237") + Fmt(Fg+"214") + n + Reset
}

func colorDetailFieldValue(n string) (d string) {
	return Bold + n + Reset
}

func colorDetailFieldSubkey(n string) (d string) {
	return detailsSection + n + Reset
}

func colorHint(n string) (d string) {
	return ColorHintsDim + n + Reset
}

func colorKeyName(n string) (d string) {
	return detailsSection + n + Reset
}

func colorKeyValue(n string) (d string) {
	return Reset + n + Reset
}

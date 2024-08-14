package display

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

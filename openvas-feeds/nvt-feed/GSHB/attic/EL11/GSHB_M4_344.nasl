# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.894344");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-01-22 13:48:09 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.344: Überwachung eines Windows Vista Systems (Windows)");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04344.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz-deprecated");

  script_tag(name:"summary", value:"IT-Grundschutz M4.344: Überwachung eines Windows Vista Systems.

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94248

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  *********************************ACHTUNG**************************************

  Diese Prüfung weicht von der offiziellen Ergänzungslieferung 11 ab.

  Die Aufgeführen Pfade und Tabellen sind Teilweise falsch:

  Der Pfad lautet (ab Vista) nicht mehr
  'Computerkonfiguration   Windows-Einstellungen   Sicherheitseinstellungen
  Lokale Richtlinien   Ereignisprotokoll'

  sondern

  'Computerkonfiguration   Administrative Vorlagen   Windows-Komponenten
  Ereignisprotokolldienst   <Protokoll>'

  Die Verweise in der Tabelle auf den 'Lokalen Gastkontogriff...' treffen für
  Windows Vista nicht mehr zu.

  Dieser Fehler wurde von der IT-Grundschutz Koordinierungsstelle
  bestätigt und wird mit der nächsten Ergänzungslieferung korrigiert.

  Hinweis:

  Die Maßnahme ist in EL11 technisch fehlerhaft.
  Der Test führt abweichend von der Maßnahme den korrekten Test aus.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

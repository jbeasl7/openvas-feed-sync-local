# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94186");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.186: Entfernen von Beispieldateien und Administrations-Scripts des IIS - Windows");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04186.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"general_note");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz-deprecated");
  script_tag(name:"summary", value:"IT-Grundschutz M4.186: Entfernen von Beispieldateien und Administrations-Scripts des IIS (Windows)

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde zudem in neueren
  EL gestrichen.

  Diese Prüfung bezieht sich auf die 10. Ergänzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);

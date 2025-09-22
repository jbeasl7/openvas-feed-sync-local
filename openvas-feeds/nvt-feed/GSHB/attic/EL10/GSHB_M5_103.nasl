# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.95103");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.103: Entfernen saemtlicher Netzwerkfreigaben beim IIS-Einsatz - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz-deprecated");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05103.html");

  script_tag(name:"summary", value:"IT-Grundschutz M5.103: Entfernen saemtlicher Netzwerkfreigaben beim IIS-Einsatz (Windows).

  ACHTUNG: Dieser Test wird nicht mehr unterstuetzt. Er wurde zudem in neueren
  EL gestrichen.

  Diese Pruefung bezieht sich auf die 10. Ergaenzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Massnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergaenzungslieferung bezieht. Titel und Inhalt koennen sich bei einer
  Aktualisierung aendern, allerdings nicht die Kernthematik.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

exit(66);

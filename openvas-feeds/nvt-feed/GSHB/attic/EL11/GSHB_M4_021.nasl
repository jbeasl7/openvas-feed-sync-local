# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.894021");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-04-13 14:21:58 +0200 (Tue, 13 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04021.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz-deprecated");
  script_tag(name:"summary", value:"IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten.

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94191

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);

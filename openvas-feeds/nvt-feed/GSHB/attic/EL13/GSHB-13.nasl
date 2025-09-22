# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94999");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-11-20 12:24:13 +0100 (Wed, 20 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, 13. EL");
  # Dependency GSHB_M4_007.nasl is running in ACT_ATTACK because it depends on
  # GSHB_SSH_TELNET_BruteForce.nasl which is in ACT_ATTACK as well.
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"general_note");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Compliance");

  script_tag(name:"summary", value:"Zusammenfassung von Tests gemäß IT-Grundschutz
(in 13. Ergänzungslieferung).

ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
den entsprechenden Test der nun permanent and die aktuelle EL angepasst
wird: OID 1.3.6.1.4.1.25623.1.0.94171

Diese Routinen prüfen sämtliche Maßnahmen des
IT-Grundschutz des Bundesamts für Sicherheit
in der Informationstechnik (BSI) auf den
Zielsystemen soweit die Maßnahmen auf automatisierte
Weise abgeprüft werden können.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

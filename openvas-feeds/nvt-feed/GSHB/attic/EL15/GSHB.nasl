# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94171");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, 15. EL");
  # Dependencies GSHB_M4_007.nasl and GSHB_M4_094.nasl are running in ACT_ATTACK because these depends on
  # GSHB_SSH_TELNET_BruteForce.nasl / GSHB_nikto.nasl which are in ACT_ATTACK as well.
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Compliance");

  script_tag(name:"summary", value:"Zusammenfassung von Tests gem der IT-Grundschutz Kataloge
  mit Stand 15. Ergnzungslieferung.

  Diese Routinen prfen smtliche Manahmen des IT-Grundschutz des Bundesamts fr Sicherheit
  in der Informationstechnik (BSI) auf den Zielsystemen soweit die Manahmen auf automatisierte
  Weise abgeprft werden knnen.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
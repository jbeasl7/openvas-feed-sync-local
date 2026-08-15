# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80044");
  script_version("2026-08-12T06:07:06+0000");
  script_tag(name:"last_modification", value:"2026-08-12 06:07:06 +0000 (Wed, 12 Aug 2026)");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SonicWall Global VPN Client Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");

  script_tag(name:"summary", value:"This script detects the installed version of
  SonicWall Global VPN Client.

  This VT has been deprecated and replaced by the VT 'SonicWall Global VPN Client (GVC) Detection
  (Windows SMB Login)' (OID: 1.3.6.1.4.1.25623.1.0.157643).");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

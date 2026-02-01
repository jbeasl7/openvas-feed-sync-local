# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105655");
  script_version("2026-01-12T05:50:06+0000");
  script_tag(name:"last_modification", value:"2026-01-12 05:50:06 +0000 (Mon, 12 Jan 2026)");
  script_tag(name:"creation_date", value:"2011-06-06 16:48:59 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Cisco IOS Software Version Detection (ssh)");

  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_tag(name:"summary", value:"Get Cisco IOS Software Version via SSH.

  This VT has been deprecated and replaced by the VT 'Cisco IOS Detection (SSH Login)'
  (OID: 1.3.6.1.4.1.25623.1.0.156114).");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);

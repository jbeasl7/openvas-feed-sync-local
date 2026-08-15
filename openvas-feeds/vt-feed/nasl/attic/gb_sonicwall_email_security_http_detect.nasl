# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103929");
  script_version("2026-08-13T06:07:26+0000");
  script_tag(name:"last_modification", value:"2026-08-13 06:07:26 +0000 (Thu, 13 Aug 2026)");
  script_tag(name:"creation_date", value:"2014-03-28 12:48:51 +0100 (Fri, 28 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SonicWall Email Security Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of SonicWall Email Security.

  This VT has been deprecated and replaced by the VT 'SonicWall Email Security Appliance Detection
  (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.157650).");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

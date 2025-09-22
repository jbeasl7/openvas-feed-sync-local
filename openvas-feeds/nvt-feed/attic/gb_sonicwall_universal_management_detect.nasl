# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105871");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-08-16 11:54:25 +0200 (Tue, 16 Aug 2016)");
  script_name("Sonicwall GMS Detection");

  script_tag(name:"summary", value:"This VT has been deprecated and replaced by the VT 'SonicWall Global Management System (GMS) /
  Universal Management Suite (USM) / Analyzer Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.107120).

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

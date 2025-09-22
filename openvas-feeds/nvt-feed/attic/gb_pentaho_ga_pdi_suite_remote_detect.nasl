# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808207");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2016-05-25 15:47:33 +0530 (Wed, 25 May 2016)");
  script_name("Pentaho Data Integration (PDI) Suite Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Pentaho Data Integration (PDI) Suite.

  This script sends an HTTP GET request and checks for the presence of
  Pentaho Data Integration (PDI) Suite from the response.

  This VT has been deprecated and merged into the VT 'Pentaho Data Integration and Analytics Detection (HTTP)'
  (OID: 1.3.6.1.4.1.25623.1.0.808205).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140778");
  script_version("2026-11-13T05:37:36+0000");
  script_tag(name:"last_modification", value:"2026-11-13 05:37:36 +0000 (Fri, 13 Nov 2026)");
  script_tag(name:"creation_date", value:"2018-02-15 17:20:38 +0700 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine NetFlow Analyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine NetFlow Analyzer.

  This VT has been deprecated and replaced by the VT 'ManageEngine NetFlow Analyzer Detection (HTTP)'
  (OID: 1.3.6.1.4.1.25623.1.0.181026).");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/netflow/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

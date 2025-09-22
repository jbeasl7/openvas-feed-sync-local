# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107586");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2019-02-16 16:04:09 +0100 (Sat, 16 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Schneider Electric Vijeo Designer Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"This VT has been deprecated and replaced by the VT
  'Schneider Electric Vijeo Designer Detection (Windows SMB Login)'
  (OID: 1.3.6.1.4.1.25623.1.0.154984).

  SMB login-based detection of Schneider Electric Vijeo Designer.");

  script_xref(name:"URL", value:"https://www.se.com/us/en/product-range/1054-vijeo-designer-hmi-software/");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

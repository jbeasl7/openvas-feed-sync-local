# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813331");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"creation_date", value:"2018-05-08 13:30:09 +0530 (Tue, 08 May 2018)");
  script_name("Trend Micro Maximum Security Detection (Windows SMB Login)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"summary", value:"Detection of installed version
  of Trend Micro Maximum Security on Windows.

  This VT has been deprecated and replaced by the VT 'Trend Micro Maximum Security Detection
  (Windows SMB Login)' (OID: 1.3.6.1.4.1.25623.1.0.118624).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

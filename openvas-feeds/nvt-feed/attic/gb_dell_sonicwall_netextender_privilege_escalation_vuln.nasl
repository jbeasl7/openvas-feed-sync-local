# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806043");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2015-4173");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-09-08 13:38:49 +0530 (Tue, 08 Sep 2015)");
  script_name("Dell SonicWall NetExtender Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"Dell SonicWall NetExtender is prone to a privilege escalation vulnerability.

  This VT has been deprecated and replaced by the VT 'Dell SonicWall NetExtender < 7.5.227, 8.x < 8.0.238 Privilege
  Escalation Vulnerability - Windows' (OID: 1.3.6.1.4.1.25623.1.0.170896).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Unquoted Windows
  search path vulnerability in the autorun value upon installation of the product.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  privileged code execution upon administrative login.");

  script_tag(name:"affected", value:"Dell SonicWall NetExtender version before
  7.5.227 and before 8.0.238 on Windows.");

  script_tag(name:"solution", value:"Upgrade to firmware version 7.5.227 or 8.0.238 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133302");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

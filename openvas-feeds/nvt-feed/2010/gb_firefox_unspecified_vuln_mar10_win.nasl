# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902147");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1122");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Unspecified Vulnerability (Mar 2010) - Windows");


  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Impact is currently unknown.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.x through 3.5.8.");
  script_tag(name:"insight", value:"Vulnerability details are not available.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"mozilla firefox is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392231.php");
  script_xref(name:"URL", value:"http://www.security-database.com/cvss.php?alert=CVE-2010-1122");
  exit(0);
}

include("version_func.inc");

fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

if(version_in_range(version:fpVer, test_version:"3.5.0", test_version2:"3.5.8")){
  report = report_fixed_ver(installed_version:fpVer, vulnerable_range:"3.5.0 - 3.5.8");
  security_message(port: 0, data: report);
}

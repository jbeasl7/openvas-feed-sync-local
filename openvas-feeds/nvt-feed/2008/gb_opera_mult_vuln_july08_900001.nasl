# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900001");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3078");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Opera for Windows Unspecified Code Execution Vulnerabilities (Jul 2008)");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");

  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/887/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30068");

  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to the way the Web Browser handles certain
  canvas functions that can cause the canvas to be painted with very small amounts of data
  constructed from random memory, which allows canvas images to be read and analyzed by JavaScript.");

  script_tag(name:"affected", value:"Opera Version 5 to 9.50 on Windows (All)");

  script_tag(name:"solution", value:"Upgrade to Opera version 9.51.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"impact", value:"Successful exploitation could grant the remote attacker
  to execute arbitrary malicious code to retrieve random samples of the user's memory, which
  may contain sensitive data.");

  exit(0);
}

include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"9.50")){
  report = report_fixed_ver(installed_version:OperaVer, vulnerable_range:"Less than or equal to 9.50");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

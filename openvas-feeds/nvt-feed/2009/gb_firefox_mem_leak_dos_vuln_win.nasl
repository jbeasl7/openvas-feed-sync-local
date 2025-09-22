# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800401");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5822");
  script_name("Firefox Browser Libxul Memory Leak Remote DoS Vulnerability - Win");
  script_xref(name:"URL", value:"http://liudieyu0.blog124.fc2.com/blog-entry-6.html");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0812-exploits/mzff_libxul_ml.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation could result in denying the service.");
  script_tag(name:"affected", value:"Firefox version 3.0.2 to 3.0.5 on Windows.");
  script_tag(name:"insight", value:"The Browser fails to validate the user input data in Libxul, which leads
  to memory consumption or crash.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"3.0.2", test_version2:"3.0.5")){
  report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.0.2 - 3.0.5");
  security_message(port: 0, data: report);
}

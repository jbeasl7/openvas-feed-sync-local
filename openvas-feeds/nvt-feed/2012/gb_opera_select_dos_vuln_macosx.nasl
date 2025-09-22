# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802754");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2009-2540", "CVE-2009-1692");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-19 10:28:43 +0530 (Thu, 19 Apr 2012)");
  script_name("Opera Web Browser Select Object Denial Of Service Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35446");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52874");
  script_xref(name:"URL", value:"http://www.g-sec.lu/one-bug-to-rule-them-all.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service.");
  script_tag(name:"affected", value:"Opera version 9.64 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an improper boundary check while passing data into
  the select() method and can be exploited by passing a large integer value
  resulting in memory exhaustion.");
  script_tag(name:"solution", value:"Upgrade to opera version 10 beta 1 or later.");
  script_tag(name:"summary", value:"Opera Web Browser is prone to select object denial of service vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"9.64")){
  report = report_fixed_ver(installed_version:operaVer, vulnerable_range:"Less than or equal to 9.64");
  security_message(port:0, data:report);
}

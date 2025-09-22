# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803311");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-1618", "CVE-2013-1637", "CVE-2013-1638", "CVE-2013-1639");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-11 14:02:27 +0530 (Mon, 11 Feb 2013)");
  script_name("Opera Multiple Vulnerabilities -01 (Feb 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57633");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57773");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1042");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1043");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1044");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1213");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code, perform distinguishing attacks and plaintext-recovery attacks or cause a denial of service.");

  script_tag(name:"affected", value:"Opera version prior to 12.13 on Mac OS X");

  script_tag(name:"insight", value:"- Does not send CORS preflight requests, this allows remote attackers to
    bypass CSRF protection mechanism via crafted site.

  - Error with particular DOM events manipulation.

  - SVG documents with crafted clipPaths allows content to overwrite memory.

  - Does not properly consider timing side-channel attacks on a MAC check
    operation during the processing of malformed CBC padding.");

  script_tag(name:"solution", value:"Upgrade to Opera version 12.13 or later.");

  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"12.13")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"12.13");
  security_message(port: 0, data: report);
  exit(0);
}

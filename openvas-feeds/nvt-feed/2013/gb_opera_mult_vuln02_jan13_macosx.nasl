# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803143");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2012-6468", "CVE-2012-6469");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-07 15:36:59 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-02 (Jan 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1037/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56594");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1036/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1212/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or disclose the information.");

  script_tag(name:"affected", value:"Opera version before 12.11 on Mac OS X");

  script_tag(name:"insight", value:"- An error in handling of error pages, can be used to guess local file paths.

  - An error when requesting pages using HTTP, causes a buffer overflow, which
    in turn can lead to a memory corruption and crash.");

  script_tag(name:"solution", value:"Upgrade to Opera version 12.11 or later.");

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

if(version_is_less(version:operaVer, test_version:"12.11")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"12.11");
  security_message(port: 0, data: report);
}

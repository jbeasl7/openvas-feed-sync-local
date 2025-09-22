# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803841");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-4973", "CVE-2013-4974");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-29 10:15:44 +0530 (Thu, 29 Aug 2013)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Aug 2013) - Windows");


  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 16.0.3.51 or later.");
  script_tag(name:"insight", value:"Flaws are due to errors when handling filenames in RMP and when parsing
RealMedia files.");
  script_tag(name:"affected", value:"RealPlayer version prior to 16.0.3.51 on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote unauthenticated attacker to obtain
sensitive information, cause a denial of service condition, or execute
arbitrary code with the privileges of the application.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61989");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61990");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/246524");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08232013_player/en");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

if(version_is_less(version:rpVer, test_version:"16.0.3.51"))
{
  report = report_fixed_ver(installed_version:rpVer, fixed_version:"16.0.3.51");
  security_message(port: 0, data: report);
  exit(0);
}

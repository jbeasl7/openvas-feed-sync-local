# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:ghost_solutions_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808573");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-5689");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-07-11 15:36:44 +0530 (Mon, 11 Jul 2016)");
  script_name("Symantec Ghost Solutions Suite Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Symantec Ghost Solutions Suite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the ghostexp.exe in
  Ghost Explorer Utility performs improper sign-extend operations before array

  - element accesses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, cause a denial of service (application
  crash), or possibly obtain sensitive information via a crafted Ghost image.");

  script_tag(name:"affected", value:"Symantec Ghost Solutions Suite (GSS) before
  3.0 HF2 (12.0.0.8010)");

  script_tag(name:"solution", value:"Update to Symantec Ghost Solutions Suite (GSS)
  3.0 HF2 (12.0.0.8010) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20150902_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76498");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_ghost_solutions_suite_detect_win.nasl");
  script_mandatory_keys("Symantec/Ghost/Solution/Suite/Installed");
  script_xref(name:"URL", value:"https://symantec.flexnetoperations.com/control/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

##https://support.symantec.com/en_US/article.TECH95856.html
if(version_is_less(version:sepVer, test_version:"12.0.0.8010"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"12.0.0.8010");
  security_message(data:report);
  exit(0);
}


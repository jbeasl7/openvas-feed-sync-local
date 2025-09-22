# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806605");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2015-4856");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-11-02 13:23:55 +0530 (Mon, 02 Nov 2015)");
  script_name("Oracle VirtualBox Unspecified Vulnerability (Nov 2015) - Windows");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to have an impact on availability.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 4.0.30,
  4.1.38, 4.2.30, 4.3.26, and 5.0.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 4.0.30, 4.1.38, 4.2.30, 4.3.26, 5.0.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77202");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\.") {
  if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.29")) {
    fix = "4.0.30";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.37")) {
    fix = "4.1.38";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.29")) {
    fix = "4.2.30";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.25")) {
    fix = "4.3.26";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805725");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2015-2594");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-07-21 10:27:00 +0530 (Tue, 21 Jul 2015)");
  script_name("Oracle VirtualBox Unspecified Vulnerability (Jul 2015) - Linux");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 4.0.32,
  4.1.40, 4.2.32, and 4.3.30 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.0.32, 4.1.40, 4.2.32, and 4.3.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75899");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\.[0-3]") {
  if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.31")) {
    fix = "4.0.32";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.39")) {
    fix = "4.1.40";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.31")) {
    fix = "4.2.32";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.29")) {
    fix = "4.3.30";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

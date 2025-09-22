# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805430");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2015-0418", "CVE-2015-0377");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-02-02 10:04:10 +0530 (Mon, 02 Feb 2015)");
  script_name("Oracle VirtualBox Multiple DoS Vulnerabilities (Feb 2015) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to conduct a denial of service attack.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions 3.2.x before 3.2.26,
  4.0.x before 4.0.28, 4.1.x before 4.1.36, 4.2.x before 4.2.28 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.2.26 or 4.0.28 or 4.1.36 or 4.2.28 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72219");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^(3\.2|4\.[0-2])") {
  if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.25")) {
    fix = "3.2.26";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.27")) {
    fix = "4.0.28";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.35")) {
    fix = "4.1.36";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.27")) {
    fix = "4.2.28";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

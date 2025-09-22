# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806603");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2015-4896", "CVE-2015-4813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-11-02 13:01:33 +0530 (Mon, 02 Nov 2015)");
  script_name("Oracle VirtualBox Multiple Unspecified Vulnerabilities-01 (Nov 2015) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to some
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on availability.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 4.0.34,
  4.1.42, 4.2.34, 4.3.32, and 5.0.8 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 4.0.34, 4.1.42, 4.2.34, 4.3.32, 5.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77185");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

if(vers =~ "^[45]\.") {
  if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.33")) {
    fix = "4.0.34";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.41")) {
    fix = "4.1.42";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.33")) {
    fix = "4.2.34";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.31")) {
    fix = "4.3.32";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.0.7")) {
    fix = "5.0.8";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806992");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2016-0495", "CVE-2015-3195");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-19 17:27:00 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"creation_date", value:"2016-01-22 16:53:27 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle VirtualBox Unspecified Vulnerability - 01 (Jan 2016) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 4.3.36
  and 5.0.14  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 4.3.36, 5.0.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.3.35")) {
  fix = "4.3.36";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.0.13")) {
  fix = "5.0.14";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

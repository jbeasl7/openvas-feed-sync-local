# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813546");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-06-26 13:48:30 +0530 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-1060", "CVE-2018-1061");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.15, 3.x < 3.4.9, 3.5.x < 3.5.6, 3.6.x < 3.6.5, 3.7.x < 3.7.0.beta3 Python Issue (Issue32981) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Python is failing to sanitize against backtracking in:

  - CVE-2018-1060: pop3lib's apop method

  - CVE-2018-1061: 'difflib.IS_LINE_JUNK' method");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to conduct
  a denial of service attack on the affected user.");

  script_tag(name:"affected", value:"Python before versions 2.7.15, 3.4.9, 3.5.6, 3.6.5
  and 3.7.0.beta3.");

  script_tag(name:"solution", value:"Update version 2.7.15, 3.4.9, 3.5.6, 3.6.5
  or 3.7.0.beta3.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue32981");
  script_xref(name:"Advisory-ID", value:"Issue32981");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.7.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.7.15", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.4.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.4.9", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.5", test_version2:"3.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.5.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.6", test_version2:"3.6.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.5", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

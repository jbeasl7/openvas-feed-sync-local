# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809216");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-5636", "CVE-2016-0772");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");
  script_tag(name:"creation_date", value:"2016-09-12 12:56:46 +0530 (Mon, 12 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("CPython Man in Middle Attack and Code Execution Vulnerabilities - Windows");

  script_tag(name:"summary", value:"CPython is prone to a man in middle attack and an arbitrary
  code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the smtplib library in CPython
  does not return an error when StartTLS fails and integer overflow error in the 'get_data'
  function in 'zipimport.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow man-in-the-middle attackers
  to bypass the TLS protections and remote attackers to cause buffer overflow.");

  script_tag(name:"affected", value:"CPython before 2.7.12, 3.x before 3.4.5, and 3.5.x
  before 3.5.2.");

  script_tag(name:"solution", value:"Update to version CPython 2.7.12, 3.4.5, 3.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://hg.python.org/cpython/rev/d590114c2394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91247");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91225");
  script_xref(name:"URL", value:"https://bugs.python.org/issue26171");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.7.12")) {
  fix = "2.7.12";
  VULN = TRUE;
}

else if(vers =~ "^3\.[0-4]") {
  if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.4.4")) {
    fix = "3.4.5";
    VULN = TRUE;
  }
}

else if(vers =~ "^3\.5") {
  if(version_in_range(version:vers, test_version:"3.5.0", test_version2:"3.5.1")) {
    fix = "3.5.2";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

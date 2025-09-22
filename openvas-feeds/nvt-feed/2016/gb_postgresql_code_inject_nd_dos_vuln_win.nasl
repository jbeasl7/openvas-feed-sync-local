# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808664");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-08-30 18:03:40 +0530 (Tue, 30 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Code Injection and Denial of Service Vulnerabilities - Windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to code injection and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error in certain nested CASE expressions.

  - Improper sanitization of input passed to database and role names.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to inject code and cause the server to crash.");

  script_tag(name:"affected", value:"PostgreSQL version before 9.1.23, 9.2.x
  before 9.2.18, 9.3.x before 9.3.14, 9.4.x before 9.4.9, and 9.5.x before
  9.5.4.");

  script_tag(name:"solution", value:"Upgrade to version 9.1.23 or 9.2.18 or
  9.3.14 or 9.4.9 or 9.5.4 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1688/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92433");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92435");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(version_is_less(version:vers, test_version:"9.1.23")) {
  fix = "9.1.23";
  VULN = TRUE;
}

else if(vers =~ "^9\.2") {
  if(version_is_less(version:vers, test_version:"9.2.18")) {
    fix = "9.2.18";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.3") {
  if(version_is_less(version:vers, test_version:"9.3.14")) {
    fix = "9.3.14";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.9")) {
    fix = "9.4.9";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.4")) {
    fix = "9.5.4";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

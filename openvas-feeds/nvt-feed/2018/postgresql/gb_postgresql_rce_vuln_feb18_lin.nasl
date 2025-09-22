# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813010");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2018-1058");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 20:11:00 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-03-09 13:07:37 +0530 (Fri, 09 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL RCE Vulnerability (Feb 2018) - Linux");

  script_tag(name:"summary", value:"PostgreSQL is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because postgresql allow a
  user to modify the behavior of a query for other users in an incorrect way.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code or crash the affected application,
  resulting in denial-of-service condition.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.22,
  9.4.x before 9.4.17, 9.5.x before 9.5.12, 9.6.x before 9.6.8 and 10.x before
  10.3.");

  script_tag(name:"solution", value:"Update to version 10.3 or 9.6.8
  or 9.5.12 or 9.4.17 or 9.3.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1834");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103221");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-10-2.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-6-7.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-5-11.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-4-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-3-21.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

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

if(vers =~ "^9\.3") {
  if(version_is_less(version:vers, test_version:"9.3.22")) {
    fix = "9.3.22";
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.17")) {
    fix = "9.4.17";
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.12")) {
    fix = "9.5.12";
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.8")) {
    fix = "9.6.8";
  }
}

else if(vers =~ "^10\.")
{
  if(version_is_less(version:vers, test_version:"10.3")) {
    fix = "10.3";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812314");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2017-12172");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-12-04 16:58:49 +0530 (Mon, 04 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Privilege Escalation Vulnerability (Dec 2017) - Linux");

  script_tag(name:"summary", value:"PostgreSQL is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as PostgreSQL runs under a
  non-root operating system account, and database superusers have effective ability
  to run arbitrary code under that system account. PostgreSQL provides a script for
  starting the database server during system boot. Packages of PostgreSQL for many
  operating systems provide their own, packager-authored startup implementations.
  Several implementations use a log file name that the database superuser can
  replace with a symbolic link. As root, they open(), chmod() and/or chown() this
  log file name. This often suffices for the database superuser to escalate to root
  privileges when root starts the server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local user
  to modify files on the target system.");

  script_tag(name:"affected", value:"PostgreSQL version 9.2.x before 9.2.24, 9.3.x
  before 9.3.20, 9.4.x before 9.4.15, 9.5.x before 9.5.10, 9.6.x before 9.6.6 and
  10.x before 10.1.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.1 or 9.6.6
  or 9.5.10 or 9.4.15 or 9.3.20 or 9.2.24 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101949");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security");

  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^9\.2") {
  if(version_is_less(version:vers, test_version:"9.2.24")) {
    fix = "9.2.24";
  }
}

else if(vers =~ "^9\.3") {
  if(version_is_less(version:vers, test_version:"9.3.20")) {
    fix = "9.3.20";
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.15")) {
    fix = "9.4.15";
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.10")) {
    fix = "9.5.10";
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.6")) {
    fix = "9.6.6";
  }
}

else if(vers =~ "^10\.") {
  if(version_is_less(version:vers, test_version:"10.1")) {
    fix = "10.1";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);

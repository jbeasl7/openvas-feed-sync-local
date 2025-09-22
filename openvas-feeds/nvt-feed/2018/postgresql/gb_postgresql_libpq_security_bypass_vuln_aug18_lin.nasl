# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813752");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2018-10915");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-08-13 18:05:39 +0530 (Mon, 13 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL 'libpq' Security Bypass Vulnerability (Aug 2018) - Linux");

  script_tag(name:"summary", value:"PostgreSQL is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an internal issue in
  the 'libpq' the client connection API for PostgreSQL where it did not reset
  all of its connection state variables when attempting to reconnect. In
  particular, the state variable that determined whether or not a password is
  needed for a connection would not be reset.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass client-side connection security features and obtain access to higher
  privileged connections or potentially cause other possible impact.");

  script_tag(name:"affected", value:"PostgreSQL versions before 10.5, 9.6.10,
  9.5.14, 9.4.19 and 9.3.24.");

  script_tag(name:"solution", value:"Update to version 10.5 or 9.6.10
  or 9.5.14 or 9.4.19 or 9.3.24 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105054");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-10-5.html#id-1.11.6.5.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-6-10.html#id-1.11.6.11.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-5-14.html#id-1.11.6.22.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-4-19.html#id-1.11.6.37.5");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/static/release-9-3-24.html#id-1.11.6.57.6");


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

if(vers =~ "^9\.3\.") {
  if(version_is_less(version:vers, test_version: "9.3.24")) {
    fix = "9.3.24";
  }
}

else if(vers =~ "^9\.4\.") {
  if(version_is_less(version:vers, test_version: "9.4.19")) {
    fix = "9.4.19";
  }
}

else if(vers =~ "^9\.5\.") {
  if(version_is_less(version:vers, test_version: "9.5.14")) {
    fix = "9.5.14";
  }
}

else if(vers =~ "^9\.6\.") {
  if(version_is_less(version:vers, test_version: "9.6.10")) {
    fix = "9.6.10";
  }
}

else if(vers =~ "^10\.") {
  if(version_is_less(version:vers, test_version: "10.5")) {
    fix = "10.5";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);

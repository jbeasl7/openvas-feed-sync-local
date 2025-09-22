# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812309");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2017-15098");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-28 10:29:00 +0000 (Tue, 28 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-12-04 16:20:41 +0530 (Mon, 04 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Information Disclosure Vulnerability (Dec 2017) - Windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the functions
  json_populate_recordset and jsonb_populate_recordset are unable to handle
  malformed invalid input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to send specially crafted data to trigger a rowtype mismatch
  in 'json{b}_populate_recordset' function to crash the target service or disclose
  potentially sensitive information.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.20,
  9.4.x before 9.4.15, 9.5.x before 9.5.10, 9.6.x before 9.6.6 and 10.x before
  10.1.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.1 or 9.6.6
  or 9.5.10 or 9.4.15 or 9.3.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101781");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security");

  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^9\.3") {
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

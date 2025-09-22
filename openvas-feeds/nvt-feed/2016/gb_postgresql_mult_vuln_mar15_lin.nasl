# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807518");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2016-0773", "CVE-2016-0766");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 20:09:00 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-03-10 19:31:43 +0530 (Thu, 10 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Multiple Vulnerabilities (Mar 2015) - Linux");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to the PostgreSQL
  incorrectly handle certain regular expressions and certain configuration
  settings (GUCS) for users of PL/Java.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to escalate privileges and to cause denial of service
  conditions.");

  script_tag(name:"affected", value:"PostgreSQL version before 9.1.20, 9.2.x
  before 9.2.15, 9.3.x before 9.3.11, 9.4.x before 9.4.6, and 9.5.x before
  9.5.1.");

  script_tag(name:"solution", value:"Upgrade to version 9.1.20 or 9.2.15 or
  9.3.11 or 9.4.6 or 9.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-2894-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83184");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1644");

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"9.1.20")) {
  fix = "9.1.20";
  VULN = TRUE;
}

else if(vers =~ "^9\.2") {
  if(version_is_less(version:vers, test_version:"9.2.15")) {
    fix = "9.2.15";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.3") {
  if(version_is_less(version:vers, test_version:"9.3.11")) {
    fix = "9.3.11";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.6")) {
    fix = "9.4.6";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.1")) {
    fix = "9.5.1";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

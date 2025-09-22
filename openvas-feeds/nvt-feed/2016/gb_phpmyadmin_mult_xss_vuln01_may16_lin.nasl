# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807595");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2016-2561");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:25:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-17 12:12:08 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("phpMyAdmin Multiple XSS Vulnerabilities (PMASA-2016-12) - Linux");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An input validation error via table/column name in database normalization
    page.

  - An input validation error in 'templates/database/structure/sortable_header.phtml'
    script in the database structure page.

  - An input validation error in 'db_central_columns.php' script in the
    central columns page.

  - An input validation error in 'normalization.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML via crafted parameters.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.4.x before 4.4.15.5 and 4.5.x before
  4.5.5.1.");

  script_tag(name:"solution", value:"Update to version 4.4.15.5, 4.5.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-12");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^4\.5" && version_is_less(version:vers, test_version:"4.5.5.1")) {
  fix = "4.5.5.1";
  VULN = TRUE;
}

else if(vers =~ "^4\.4" && version_is_less(version:vers, test_version:"4.4.15.5")) {
  fix = "4.4.15.5";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

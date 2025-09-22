# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805965");
  script_version("2023-10-06T16:09:51+0000");
  script_cve_id("CVE-2015-6661", "CVE-2015-6660", "CVE-2015-6658");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-08-28 12:25:16 +0530 (Fri, 28 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal 6.x < 6.37, 7.x < 7.39 Multiple Vulnerabilities (SA-CORE-2015-003) - Linux");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - The Form API in the application does not properly validate the form token.

  - There is no restriction to get node titles by reading the menu.

  - Insufficient sanitization of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information, execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site and
  conduct CSRF attacks.");

  script_tag(name:"affected", value:"Drupal 6.x before 6.37 and 7.x before 7.39
  on Linux.");

  script_tag(name:"solution", value:"Update to version 6.37, 7.39 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2015-003");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^[67]\.") {
  if(version_in_range(version:version, test_version:"6.0", test_version2:"6.36")) {
    fix = "6.37";
    VULN = TRUE;
  }

  if(version_in_range(version:version, test_version:"7.0", test_version2:"7.38")) {
    fix = "7.39";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

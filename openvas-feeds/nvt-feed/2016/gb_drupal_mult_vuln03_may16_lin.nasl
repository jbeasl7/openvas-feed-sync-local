# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808047");
  script_version("2023-10-06T16:09:51+0000");
  script_cve_id("CVE-2016-3170", "CVE-2016-3162");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-22 14:11:00 +0000 (Fri, 22 Apr 2016)");
  script_tag(name:"creation_date", value:"2016-05-18 16:31:32 +0530 (Wed, 18 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal 7.x < 7.43, 8.x < 8.0.4 Multiple Vulnerabilities (SA-CORE-2016-001) - Linux");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An email address can be matched to an account.

  - An improper validation of File module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause information disclosure, bypass access restrictions and
  read, delete, or substitute a link to a file.");

  script_tag(name:"affected", value:"Drupal 7.x before 7.43 and 8.x before
  8.0.4 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.43, 8.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version =~ "^[78]\.") {
  if(version_in_range(version:version, test_version:"7.0", test_version2:"7.42")) {
    fix = "7.43";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.0.0", test_version2:"8.0.3")) {
    fix = "8.0.4";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

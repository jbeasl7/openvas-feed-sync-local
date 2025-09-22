# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808044");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-3168", "CVE-2016-3163", "CVE-2016-3169");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 14:33:00 +0000 (Thu, 14 Apr 2016)");
  script_tag(name:"creation_date", value:"2016-05-18 16:01:10 +0530 (Wed, 18 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Drupal 6.x < 6.38, 7.x < 7.43 Multiple Vulnerabilities (SA-CORE-2016-001) - Windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An improper validation of JSON-encoded content in system module.

  - The XML-RPC system allows a large number of calls to the same method.

  - An error in 'user_save' function in User module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause brute force attacks, to download and execute JSON-encoded
  content and also to gain elevated privileges.");

  script_tag(name:"affected", value:"Drupal 6.x before 6.38 and 7.x before 7.43
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 6.38 or 7.43 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

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
  if(version_in_range(version:version, test_version:"6.0", test_version2:"6.37")) {
    fix = "6.38";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"7.0", test_version2:"7.42")) {
    fix = "7.43";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

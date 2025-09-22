# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812583");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2018-7600");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-27 21:25:54 +0000 (Mon, 27 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-03-29 09:55:26 +0530 (Thu, 29 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Drupal Core Critical RCE Vulnerability (SA-CORE-2018-002) - Windows, Version Check");

  script_tag(name:"summary", value:"Drupal is prone to a critical remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within multiple subsystems of Drupal. This
  potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could
  result in the site being completely compromised.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code and completely compromise the site.");

  script_tag(name:"affected", value:"Drupal core versions 6.x and prior, 7.x prior to 7.58, 8.2.x
  and prior, 8.3.x prior to 8.3.9, 8.4.x prior to 8.4.6 and 8.5.x prior to 8.5.1.");

  script_tag(name:"solution", value:"Update to version 7.58, 8.3.9, 8.4.6, 8.5.1 or later. Please
  see the referenced links for available updates.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2018-001");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-002");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.58");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.3.9");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.4.6");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.5.1");
  script_xref(name:"URL", value:"https://research.checkpoint.com/uncovering-drupalgeddon-2/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, version_regex:"^([0-9.]+)", exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^6\.") {
  fix = "Drupal 6 is End of Life. Please contact a Drupal 6 LTS vendor.";
}

if(version =~ "^8\.2" || version == "8.5.0") {
  fix = "8.5.1";
}

if(version =~ "^8\.3" && version_in_range(version:version, test_version:"8.3.0", test_version2:"8.3.8")) {
  fix = "8.3.9";
}

if(version =~ "^8\.4" && version_in_range(version:version, test_version:"8.4.0", test_version2:"8.4.5")) {
  fix = "8.4.6";
}

if(version =~ "^7\." && version_in_range(version:version, test_version:"7.0", test_version2:"7.57")) {
  fix = "7.58";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

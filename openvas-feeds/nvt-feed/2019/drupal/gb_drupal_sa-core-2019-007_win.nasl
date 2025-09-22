# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142386");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-05-09 09:46:02 +0000 (Thu, 09 May 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 16:29:00 +0000 (Wed, 29 Sep 2021)");

  script_cve_id("CVE-2019-11831");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Third-party Libraries Vulnerability (SA-CORE-2019-007) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a vulnerability in the 3rd party library Phar Stream Wrapper.");

  script_tag(name:"insight", value:"The vulnerability lies in third-party dependencies included in or required by
  Drupal core. As described in TYPO3-PSA-2019-007 (By-passing protection of Phar Stream Wrapper Interceptor).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.6.x or earlier and 8.7.0.");

  script_tag(name:"solution", value:"Update to version 7.67, 8.6.16, 8.7.1 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-007");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-psa-2019-007/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.66")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.67", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

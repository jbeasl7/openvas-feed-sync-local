# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124658");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-05-28 10:13:34 +0000 (Tue, 28 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-34506", "CVE-2024-34507");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.39.7, 1.40.x < 1.40.3, 1.41.x < 1.41.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-34506: If a user with the necessary rights to move the page opens special move page
  for a page with tens of thousands of subpages, then the page will exceed the maximum request
  time, leading to a denial of service.

  - CVE-2024-34507: XSS can occur because of mishandling of the 0x1b character.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.39.7, 1.40.x prior to version
  1.40.3 and 1.41.x prior to version 1.41.1.");

  script_tag(name:"solution", value:"Update to version 1.39.7, 1.40.3, 1.41.1 or later.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T357760");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T355538");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.39.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.40.0", test_version2: "1.40.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.40.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.41.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.41.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

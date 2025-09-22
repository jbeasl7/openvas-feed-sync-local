# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146840");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-10-05 13:56:43 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 20:40:00 +0000 (Mon, 18 Oct 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-41798", "CVE-2021-41799", "CVE-2021-41800");

  script_name("MediaWiki < 1.31.16, 1.32.x < 1.35.4, 1.36.x < 1.36.2 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-41798: XSS in Special:Search

  - CVE-2021-41799: ApiQueryBacklinks can cause a full table scan

  - CVE-2021-41800: PoolCounter protection");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.31.16, version 1.32.x through
  1.35.3 and 1.36.x through 1.36.1.");

  script_tag(name:"solution", value:"Update to version 1.31.16, 1.35.4, 1.36.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/2IFS5CM2YV4VMSODPX3J2LFHKSEWVFV5/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T285515");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T290379");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T284419");

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

if (version_is_less(version: version, test_version: "1.31.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.32.0", test_version2: "1.35.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.36.0", test_version2: "1.36.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

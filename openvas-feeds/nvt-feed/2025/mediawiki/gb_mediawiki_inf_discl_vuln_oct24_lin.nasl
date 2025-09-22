# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171466");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-06 17:41:43 +0000 (Tue, 06 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-47913");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.39.9, 1.40.x < 1.41.3, 1.42.x < 1.42.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An API caller can match a filter condition against AbuseFilter
  logs even if the caller is not authorized to view the log details for the filter.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.39.9, 1.40.x prior to 1.41.3 and
  1.42.x prior to 1.42.2.");

  script_tag(name:"solution", value:"Update to version 1.39.9, 1.41.3, 1.42.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/NPSACWFMNGERKIHNQWYASXCSAY26OYGN/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T372998");

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

if (version_is_less(version: version, test_version: "1.39.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.40.0", test_version_up: "1.41.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.41.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.42.0", test_version_up: "1.42.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.42.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

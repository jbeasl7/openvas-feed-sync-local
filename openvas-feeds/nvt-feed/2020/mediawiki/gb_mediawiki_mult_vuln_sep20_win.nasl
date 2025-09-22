# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144682");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-09-30 06:45:50 +0000 (Wed, 30 Sep 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-10 11:15:00 +0000 (Sun, 10 Jan 2021)");

  script_cve_id("CVE-2020-25813", "CVE-2020-25812", "CVE-2020-25815", "CVE-2020-17367", "CVE-2020-17368",
                "CVE-2020-25814", "CVE-2020-25828", "CVE-2020-25869", "CVE-2020-25827", "CVE-2020-26120",
                "CVE-2020-26121");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities (Sep 2020) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities were fixed:

  - SpecialUserrights: If a viewer lacks 'hideuser', ignore hidden users (CVE-2020-25813)

  - Unescaped message used in HTML on Special:Contributions (CVE-2020-25812)

  - Unescaped message used in HTML within LogEventsList (CVE-2020-25815)

  - Prevent invoking firejail's --output functionality (CVE-2020-17367, CVE-2020-17368)

  - mediawiki.jqueryMsg: Sanitize URLs and 'style' attribute (CVE-2020-25814)

  - Escape HTML in mw.message( ... ).parse() (CVE-2020-25828)

  - ActorMigration: Load user from the correct database (CVE-2020-25869)

  - Ensure actor ID from correct wiki is used (CVE-2020-25869)

  - TOTP throttle not enforced cross-wiki (CVE-2020-25827)

  - XSS  in the MobileFrontend extension (CVE-2020-26120)

  - An issue was discovered in the FileImporter extension (CVE-2020-26121)");

  script_tag(name:"affected", value:"MediaWiki versions before 1.31.10 and 1.34.4.");

  script_tag(name:"solution", value:"Update to version 1.31.10, 1.34.4 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-l/2020-September/048488.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-l/2020-September/048480.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.31.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.32.0", test_version2: "1.34.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.34.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

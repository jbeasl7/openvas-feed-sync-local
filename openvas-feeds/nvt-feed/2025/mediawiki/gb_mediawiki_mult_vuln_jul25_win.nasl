# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127926");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-14 07:10:43 +0000 (Mon, 14 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-6589", "CVE-2025-6590", "CVE-2025-6591", "CVE-2025-6592",
                "CVE-2025-6593", "CVE-2025-6594", "CVE-2025-6595", "CVE-2025-6596",
                "CVE-2025-6597", "CVE-2025-6926", "CVE-2025-6927", "CVE-2025-32072");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.39.13, 1.40.x < 1.42.7, 1.43.x < 1.43.2 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-6589: BlockList: rows contains suppressed users

  - CVE-2025-6590: Unescaped usernames in HTMLUserTextField

  - CVE-2025-6591: Unescaped i18n messages in feedcontributions action

  - CVE-2025-6592: Creating a permanent account from a temporary account associates temp username
  and IP address with real username in AbuseLog

  - CVE-2025-6593: IP leak to unverified email

  - CVE-2025-6594: A reflected XSS in apisandbox when invalid 'format' is provided

  - CVE-2025-6595: Stored XSS through system messages in MultimediaViewer

  - CVE-2025-6596: Vector inserts portlet labels as HTML, allowing for stored XSS through system
  messages.

  - CVE-2025-6597: Autocreation is treated as login for reauthentication

  - CVE-2025-6926: CentralAuth Extension allows Bypass Authentication

  - CVE-2025-6927: Leak of hidden usernames via autoblocks of users

  - CVE-2025-32072: Feed Utils allows WebView Injection");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.39.13, 1.40.x prior to 1.42.7,
  and 1.43.x prior to 1.43.2.");

  script_tag(name:"solution", value:"Update to version 1.39.13, 1.42.7, 1.43.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/TT45WDZ7MDTXXBEFLBMLAJI532O2PN2U/");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/C3ZZDKSFH2PW55GRH6Y4SXIM37GBXL32/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T391343");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T392746");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T392276");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T391218");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T396230");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T31856");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T395063");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T394863");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T396685");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T389009");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T389010");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T397595");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T386175");

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

if (version_is_less(version: version, test_version: "1.39.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.40", test_version_up: "1.42.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.42.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.43", test_version_up: "1.43.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.43.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

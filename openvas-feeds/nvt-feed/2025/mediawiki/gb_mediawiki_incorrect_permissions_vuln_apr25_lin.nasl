# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171462");
  script_version("2025-05-07T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-07 05:40:10 +0000 (Wed, 07 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-02 21:07:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-32697");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.42.6, 1.43.x < 1.43.1 Incorrect Permissions Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to an incorrect permissions
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An improper preservation of permissions vulnerability exists
  in the includes/editpage/IntroMessageBuilder.Php, includes/Permissions/PermissionManager.Php,
  includes/Permissions/RestrictionStore.Php files.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.42.6 and 1.43.x prior to
  1.43.1.");

  script_tag(name:"solution", value:"Update to version 1.42.6, 1.43.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/CIXFJVC57OFRBCCEIDRLZCLFGMYGEYTT/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T140010");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T24521");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T62109");

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

if (version_is_less(version: version, test_version: "1.42.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.42.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.43.0", test_version_up: "1.43.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.43.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

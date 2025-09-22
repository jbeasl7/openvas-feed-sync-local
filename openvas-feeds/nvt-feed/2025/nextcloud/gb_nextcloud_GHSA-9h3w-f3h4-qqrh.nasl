# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154511");
  script_version("2025-05-21T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-21 05:40:19 +0000 (Wed, 21 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-20 02:18:31 +0000 (Tue, 20 May 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2025-47790");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Session Handling Vulnerability (GHSA-9h3w-f3h4-qqrh)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a session handling
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A bug with the session handling causes skipping the second
  factor confirmation after a successful login with the username and password when the server is
  configured with remember_login_cookie_lifetime set to 0, once the session expired on the page to
  select the second factor and the page is reloaded.");

  script_tag(name:"affected", value:"Nextcloud Server prior to version 26.0.13.15, 27.x prior
  to 27.1.11.15, 28.x prior to 28.0.14.6, 29.x prior to 29.0.15, 30.x prior to 30.0.9 and 31.x
  prior to 31.0.3.");

  script_tag(name:"solution", value:"Update to version 26.0.13.15, 27.1.11.15, 28.0.14.6, 29.0.15,
  30.0.9, 31.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-9h3w-f3h4-qqrh");

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

if (version_is_less(version: version, test_version: "26.0.13.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.0.13.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "27.0.0", test_version_up: "27.1.11.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "27.1.11.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "28.0.0", test_version_up: "28.0.14.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.0.14.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "29.0.0", test_version_up: "29.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "29.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "30.0.0", test_version_up: "30.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "30.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "31.0.0", test_version_up: "31.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "31.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

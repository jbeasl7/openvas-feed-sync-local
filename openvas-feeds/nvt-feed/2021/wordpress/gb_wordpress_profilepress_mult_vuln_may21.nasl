# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:properfraction:profilepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146796");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-09-28 14:52:27 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 21:09:00 +0000 (Thu, 08 Jul 2021)");

  script_cve_id("CVE-2021-34621", "CVE-2021-34622", "CVE-2021-34623", "CVE-2021-34624");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin 3.0.0 < 3.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-user-avatar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ProfilePress (Formerly WP User Avatar)' is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-34621: Possibility for users to register on sites as an administrator

  - CVE-2021-34622: Possibility for users to escalate their privileges to that of an administrator
  while editing their profile

  - CVE-2021-34623: Possibility for users to upload arbitrary files during user registration or
  during profile updates

  - CVE-2021-34624: Possibility for users to upload arbitrary files during user registration or
  during profile updates");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin version 3.0.0 through 3.1.3.");

  script_tag(name:"solution", value:"Update to version 3.1.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/06/easily-exploitable-critical-vulnerabilities-patched-in-profilepress-plugin/");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

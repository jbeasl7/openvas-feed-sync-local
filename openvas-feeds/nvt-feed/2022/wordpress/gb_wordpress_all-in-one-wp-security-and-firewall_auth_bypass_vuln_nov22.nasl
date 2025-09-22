# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tipsandtricks-hq:all_in_one_wp_security_%26_firewall";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127279");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-12-13 06:15:43 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-15 14:01:00 +0000 (Thu, 15 Dec 2022)");

  script_cve_id("CVE-2022-4097");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All In One WP Security & Firewall Plugin < 5.0.8 Authorization Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-wp-security-and-firewall/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All In One WP Security & Firewall'
  is prone to an authorization bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is susceptible to IP Spoofing attacks, which can
  lead to bypassed security features (like IP blocks, rate limiting, brute force protection, and
  more).");

  script_tag(name:"affected", value:"WordPress All In One WP Security & Firewall plugin prior to
  version 5.0.8.");

  script_tag(name:"solution", value:"Update to version 5.0.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/15819d33-7497-4f7d-bbb8-b3ab147806c4");

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

if (version_is_less(version: version, test_version: "5.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

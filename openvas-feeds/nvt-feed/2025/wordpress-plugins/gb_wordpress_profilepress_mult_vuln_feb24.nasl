# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:properfraction:profilepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124724");
  script_version("2025-04-09T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-09 05:39:51 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-05 08:11:08 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-22 16:38:11 +0000 (Wed, 22 Jan 2025)");

  script_cve_id("CVE-2024-1408", "CVE-2024-1519", "CVE-2024-1570");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin < 4.15.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-user-avatar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ProfilePress' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-1408: Authenticated stored cross-site scripting via the plugin's
  edit-profile-text-box shortcode

  - CVE-2024-1519: Unauthenticated stored cross-site scripting via the 'name' parameter

  - CVE-2024-1570: Authenticated stored cross-site scripting via login-password shortcode");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin prior to version 4.15.0.");

  script_tag(name:"solution", value:"Update to version 4.15.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-user-avatar/profilepress-4144-authenticated-contributor-stored-cross-site-scripting-via-edit-profile-text-box-shortcode");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-user-avatar/paid-membership-plugin-ecommerce-user-registration-form-login-form-user-profile-restrict-content-profilepress-4144-unauthenticated-stored-cross-site-scripting");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-user-avatar/profilepress-4144-authenticated-contributor-stored-cross-site-scripting-via-shortcode");

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

if (version_is_less(version: version, test_version: "4.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

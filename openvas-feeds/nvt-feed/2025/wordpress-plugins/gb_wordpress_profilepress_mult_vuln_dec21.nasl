# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:properfraction:profilepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124723");
  script_version("2025-04-09T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-09 05:39:51 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-05 08:11:08 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 15:28:23 +0000 (Thu, 16 Dec 2021)");

  script_cve_id("CVE-2021-24954", "CVE-2021-24955");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin < 3.2.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-user-avatar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ProfilePress' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-24954: Reflected cross-site scripting via ppress_cc_data parameter

  - CVE-2021-24955: Reflected cross-site scripting via pp_get_forms_by_builder_type parameter");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin prior to version 3.2.3.");

  script_tag(name:"solution", value:"Update to version 3.2.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-user-avatar/profilepress-322-reflected-cross-site-scripting-via-ppress-cc-data-parameter");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-user-avatar/profilepress-322-reflected-cross-site-scripting");

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

if (version_is_less(version: version, test_version: "3.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

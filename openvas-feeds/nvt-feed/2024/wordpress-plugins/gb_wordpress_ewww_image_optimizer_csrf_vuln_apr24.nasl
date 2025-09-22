# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ewww:image_optimizer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126785");
  script_version("2024-05-09T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-05-09 05:05:43 +0000 (Thu, 09 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-20 15:20:45 +0000 (Sat, 20 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2024-31924");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress EWWW Image Optimizer Plugin < 7.3.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ewww-image-optimizer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'EWWW Image Optimizer' is prone to an
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WWW EWWW Image Optimizer allows to cross-site request forgery
  (CSRF).");

  script_tag(name:"affected", value:"WordPress EWWW Image Optimizer plugin prior to version
  7.3.0.");

  script_tag(name:"solution", value:"Update to version 7.3.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/ewww-image-optimizer/wordpress-ewww-image-optimizer-plugin-7-2-3-cross-site-request-forgery-csrf-vulnerability?_s_id=cve");

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

if (version_is_less(version: version, test_version: "7.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

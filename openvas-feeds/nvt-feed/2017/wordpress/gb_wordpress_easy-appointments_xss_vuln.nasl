# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:easy_appointments_project:easy_appointments";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112102");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-11-03 14:18:51 +0200 (Fri, 03 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-17 16:47:00 +0000 (Fri, 17 Nov 2017)");

  script_cve_id("CVE-2017-15812");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Easy Appointments Plugin < 1.12.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/easy-appointments/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Easy Appointments' is prone to a cross-site
  scripting (XSS) vulnerability via a settings values in the admin panel.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Easy Appointments plugin before 1.12.0.");

  script_tag(name:"solution", value:"Update to version 1.12.0 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8937");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/easy-appointments/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.12.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.12.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

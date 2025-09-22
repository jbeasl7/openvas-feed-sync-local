# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112423");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-11-13 12:09:00 +0100 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-05 13:55:00 +0000 (Thu, 05 Jul 2018)");

  script_cve_id("CVE-2018-11579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Woocommerce Category Banner Management Plugin <= 1.1.0 Unauthenticated Settings Change Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/banner-management-for-woocommerce/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Woocommerce Category Banner Management' is
  prone to an unauthenticated settings change vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Woocommerce Category Banner plugin through version
  1.1.0.");

  script_tag(name:"solution", value:"Update to version 1.1.1 or later.");

  script_xref(name:"URL", value:"http://labs.threatpress.com/unauthenticated-settings-change-vulnerability-in-woocommerce-category-banner-management-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/banner-management-for-woocommerce/#developers");
  exit(0);
}

CPE = "cpe:/a:multidots:woocommerce_category_banner_management";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

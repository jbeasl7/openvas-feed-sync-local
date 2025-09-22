# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112486");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-07 19:35:00 +0000 (Thu, 07 Feb 2019)");
  script_tag(name:"creation_date", value:"2019-01-16 11:33:11 +0100 (Wed, 16 Jan 2019)");

  script_cve_id("CVE-2017-18356");

  script_name("WordPress WooCommerce Plugin < 3.2.4 Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce' is prone to
  a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attack is possible after gaining access to the target site with a
  user account that has at least Shop manager privileges. The attacker then constructs a specifically
  crafted string that will turn into a PHP object injection involving the includes/shortcodes/class-wc-shortcode-products.php WC_Shortcode_Products::get_products()
  use of cached queries within shortcodes.");

  script_tag(name:"affected", value:"WooCommerce plugin for WordPress prior to version 3.2.4.

  Additionally this issue is only present in WordPress version >= 4.8.3.");

  script_tag(name:"solution", value:"Upgrade WooCommerce to version 3.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/woocommerce-php-object-injection/");
  script_xref(name:"URL", value:"https://woocommerce.wordpress.com/2017/11/16/woocommerce-3-2-4-security-fix-release-notes/");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce/detected");

  exit(0);
}

CPE = "cpe:/a:automattic:woocommerce";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

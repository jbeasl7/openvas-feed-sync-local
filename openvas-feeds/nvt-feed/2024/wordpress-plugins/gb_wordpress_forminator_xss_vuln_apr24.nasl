# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:incsub:forminator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103097");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-05-10 10:10:00 +0000 (Fri, 10 May 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:29:45 +0000 (Tue, 04 Feb 2025)");

  script_cve_id("CVE-2024-3053");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Forminator Plugin < 1.29.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/forminator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Forminator' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The WordPress 'Forminator' plugin allows cross-site scripting
  attacks due to insufficient input sanitization and output escaping on the 'id' forminator_form
  shortcode attribute.");

  script_tag(name:"impact", value:"Attackers with contributor-level and above permissions are able
  to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected
  page.");

  script_tag(name:"affected", value:"WordPress Popup Maker plugin prior to version 1.29.3.");

  script_tag(name:"solution", value:"Update to version 1.29.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/forminator/forminator-contact-form-payment-form-custom-form-builder-1292-authenticated-contributor-stored-cross-site-scripting");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.29.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.29.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

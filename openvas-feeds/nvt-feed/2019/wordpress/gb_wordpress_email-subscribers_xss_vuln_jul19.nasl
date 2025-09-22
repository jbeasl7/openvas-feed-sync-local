# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112620");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-08-07 11:52:00 +0000 (Wed, 07 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 19:11:00 +0000 (Fri, 03 Mar 2023)");

  script_cve_id("CVE-2019-14364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Email Subscribers Plugin < 4.1.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/email-subscribers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Email Subscribers & Newsletters' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a
  remote attacker to inject arbitrary JavaScript commands into an affected site.");

  script_tag(name:"affected", value:"WordPress Email Subscribers & Newsletters plugin before
  version 4.1.7.");

  script_tag(name:"solution", value:"Update to version 4.1.7 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/email-subscribers/#developers");
  script_xref(name:"URL", value:"https://github.com/ivoschyk-cs/CVE-s/blob/master/Email%20Subscribers%20%26%20Newsletters%20Wordpress%20Plugin%20(XSS)");

  exit(0);
}

CPE = "cpe:/a:icegram:email_subscribers_%26_newsletters";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.1.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

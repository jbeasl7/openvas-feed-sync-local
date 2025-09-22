# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpexperts:post_smtp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170191");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2022-10-04 14:04:48 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 16:37:00 +0000 (Wed, 28 Sep 2022)");

  script_cve_id("CVE-2022-2352");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Post SMTP Mailer/Email Log Plugin < 2.1.7 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/post-smtp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Post SMTP Mailer/Email Log' is prone to a
  server-side request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have proper authorisation in some AJAX
  actions, which could allow high privilege users such as admin to perform blind SSRF on multisite
  installations for example.");

  script_tag(name:"affected", value:"WordPress Post SMTP Mailer/Email Log plugin prior to version 2.1.7.");

  script_tag(name:"solution", value:"Update to version 2.1.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/dc99ac40-646a-4f8e-b2b9-dc55d6d4c55c");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"2.1.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.1.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpexperts:post_smtp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170803");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-08-14 08:59:07 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 09:15:52 +0000 (Thu, 11 Jan 2024)");

  script_cve_id("CVE-2023-6620", "CVE-2023-6621", "CVE-2023-6629", "CVE-2023-6875");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Post SMTP Mailer/Email Log Plugin < 2.8.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/post-smtp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Post SMTP Mailer/Email Log' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-6620: SQL injection

  - CVE-2023-6621: Reflected cross-site scripting (XSS)

  - CVE-2023-6629: Reflected cross-site scripting (XSS) via 'msg' parameter

  - CVE-2023-6875: Authorization bypass via type connect-app API");

  script_tag(name:"affected", value:"WordPress Post SMTP Mailer/Email Log plugin prior to
  version 2.8.7.");

  script_tag(name:"solution", value:"Update to version 2.8.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ab5c42ca-ee7d-4344-bd88-0d727ed3d9c4/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b49ca336-5bc2-4d72-a9a5-b8c020057928/");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/post-smtp/post-smtp-mailer-286-reflected-cross-site-scripting-via-msg");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/post-smtp/post-smtp-mailer-email-log-delivery-failure-notifications-and-best-mail-smtp-for-wordpress-287-authorization-bypass-via-type-connect-app-api");

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

if( version_is_less( version:version, test_version:"2.8.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.8.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108068");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5610", "CVE-2017-5611", "CVE-2017-5612", "CVE-2017-1001000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:37:00 +0000 (Sat, 30 Jan 2021)");
  script_tag(name:"creation_date", value:"2017-02-02 14:20:15 +0100 (Thu, 02 Feb 2017)");
  script_name("WordPress < 4.7.2 Multiple Security Vulnerabilities - Linux");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://make.wordpress.org/core/2017/02/01/disclosure-of-additional-security-fix-in-wordpress-4-7-2/");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/");
  script_xref(name:"URL", value:"https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html");
  script_xref(name:"URL", value:"http://www.secpod.com/blog/wordpress-rest-api-zero-day-privilege-escalation-vulnerability");

  script_tag(name:"summary", value:"WordPress is prone to multiple security vulnerabilities because it fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The user interface for assigning taxonomy terms in Press This is shown to
  users who do not have permissions to use it.

  - P_Query is vulnerable to a SQL injection (SQLi) when passing unsafe data.
  WordPress core is not directly vulnerable to this issue, but hardening was added to prevent plugins and themes
  from accidentally causing a vulnerability.

  - A cross-site scripting (XSS) vulnerability was discovered in the posts list table.

  - An unauthenticated privilege escalation vulnerability was discovered in a REST API endpoint.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to e.g. obtain sensitive information or inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"WordPress versions 4.7.1 and earlier.");

  script_tag(name:"solution", value:"Update to WordPress version 4.7.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.7.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.7.2" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108046");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5493", "CVE-2017-5492", "CVE-2017-5491", "CVE-2017-5490",
                "CVE-2017-5489", "CVE-2017-5488", "CVE-2017-5487", "CVE-2016-10066");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-01-20 12:20:15 +0100 (Fri, 20 Jan 2017)");
  script_name("WordPress < 4.7.1 Multiple Security Vulnerabilities - Linux");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://wpvulndb.com/wordpresses/47");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/");

  script_tag(name:"summary", value:"WordPress is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Cross-site scripting (XSS) via the plugin name or version header on update-core.php

  - Cross-site request forgery (CSRF) bypass via uploading a Flash file

  - Cross-site scripting (XSS) via theme name fallback

  - Post via email checks mail.example.com if default settings are not changed

  - Cross-site request forgery (CSRF) in the accessibility mode of widget editing

  - Weak cryptographic security for multisite activation key");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to e.g. obtain sensitive information or inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"WordPress versions 4.7 and earlier on Linux.");

  script_tag(name:"solution", value:"Update to WordPress version 4.7.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.7.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.7.1" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

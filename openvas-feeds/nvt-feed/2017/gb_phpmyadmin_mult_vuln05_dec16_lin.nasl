# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108133");
  script_version("2024-02-29T14:37:57+0000");
  script_tag(name:"last_modification", value:"2024-02-29 14:37:57 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)");
  script_cve_id("CVE-2016-9866", "CVE-2016-9865", "CVE-2016-9864", "CVE-2016-9861", "CVE-2016-9860",
                "CVE-2016-9859", "CVE-2016-9858", "CVE-2016-9857", "CVE-2016-9856", "CVE-2016-9850",
                "CVE-2016-9849", "CVE-2016-9848", "CVE-2016-9847");
  script_name("phpMyAdmin Multiple Security Vulnerabilities - 04 (Dec 2016) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 4.6.x prior to 4.6.5, 4.4.x prior to 4.4.15.9, and 4.0.x prior to 4.0.10.18.");

  script_tag(name:"solution", value:"Update to version 4.6.5, 4.4.15.9 or 4.0.10.18.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers =~ "^4\.0\." ) {
  if( version_is_less( version:vers, test_version:"4.0.10.18" ) ) {
    vuln = TRUE;
    fix = "4.0.10.18";
  }
}

if( vers =~ "^4\.4\." ) {
  if( version_is_less( version:vers, test_version:"4.4.15.9" ) ) {
    vuln = TRUE;
    fix = "4.4.15.9";
  }
}

if( vers =~ "^4\.6\." ) {
  if( version_is_less( version:vers, test_version:"4.6.5" ) ) {
    vuln = TRUE;
    fix = "4.6.5";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

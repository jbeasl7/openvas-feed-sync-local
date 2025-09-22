# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108129");
  script_version("2024-02-29T14:37:57+0000");
  script_tag(name:"last_modification", value:"2024-02-29 14:37:57 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");
  script_cve_id("CVE-2016-6633", "CVE-2016-6632", "CVE-2016-6631", "CVE-2016-6630", "CVE-2016-6629",
                "CVE-2016-6628", "CVE-2016-6627", "CVE-2016-6626", "CVE-2016-6625", "CVE-2016-6624",
                "CVE-2016-6623", "CVE-2016-6622", "CVE-2016-6620", "CVE-2016-6619", "CVE-2016-6618",
                "CVE-2016-6614", "CVE-2016-6613", "CVE-2016-6612", "CVE-2016-6611", "CVE-2016-6610",
                "CVE-2016-6609", "CVE-2016-6607", "CVE-2016-6606");
  script_name("phpMyAdmin Multiple Security Vulnerabilities - 02 (Dec 2016) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 4.6.x prior to 4.6.4, 4.4.x prior to 4.4.15.8, and 4.0.x prior to 4.0.10.17.");

  script_tag(name:"solution", value:"Update to version 4.6.4, 4.4.15.8 or 4.0.10.17.");

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
  if( version_is_less( version:vers, test_version:"4.0.10.17" ) ) {
    vuln = TRUE;
    fix = "4.0.10.17";
  }
}

if( vers =~ "^4\.4\." ) {
  if( version_is_less( version:vers, test_version:"4.4.15.8" ) ) {
    vuln = TRUE;
    fix = "4.4.15.8";
  }
}

if( vers =~ "^4\.6\." ) {
  if( version_is_less( version:vers, test_version:"4.6.4" ) ) {
    vuln = TRUE;
    fix = "4.6.4";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

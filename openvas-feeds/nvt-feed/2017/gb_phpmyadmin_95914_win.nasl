# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108076");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2017-02-07 15:18:02 +0100 (Tue, 07 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 19:11:00 +0000 (Mon, 25 Mar 2019)");
  script_cve_id("CVE-2016-6621", "CVE-2017-1000013", "CVE-2017-1000014", "CVE-2017-1000015", "CVE-2017-1000016",
                "CVE-2017-1000017", "CVE-2017-1000018");
  script_name("phpMyAdmin 4.0.x < 4.0.10.19, 4.4.x < 4.4.15.10, 4.6.x < 4.6.6 Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to:

  - bypass security restrictions and perform unauthorized actions. This may aid in further attacks (CVE-2016-6621).

  - to redirect to insecure using special request path (CVE-2017-1000013)

  - cause CSS injection in themes by crafted cookie parameters (CVE-2017-1000015)

  - inject arbitrary values in the browser cookies (CVE-2017-1000016)

  - connect to an arbitrary MySQL server (CVE-2017-1000017)

  - cause a DOS attack (CVE-2017-1000014, CVE-2017-1000018)");

  script_tag(name:"affected", value:"phpMyAdmin 4.6.x prior to 4.6.6, 4.4.x prior to 4.4.15.10, and
  4.0.x prior to 4.0.10.19.");

  script_tag(name:"solution", value:"Update to version 4.6.6, 4.4.15.10, 4.0.10.19 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-44/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-1/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-3/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-4/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-5/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-6/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-7/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95914");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers =~ "^4\.0" ) {
  if( version_is_less( version:vers, test_version:"4.0.10.19" ) ) {
    vuln = TRUE;
    fix = "4.0.10.19";
  }
}

if( vers =~ "^4\.4" ) {
  if( version_is_less( version:vers, test_version:"4.4.15.10" ) ) {
    vuln = TRUE;
    fix = "4.4.15.10";
  }
}

if( vers =~ "^4\.6" ) {
  if( version_is_less( version:vers, test_version:"4.6.6" ) ) {
    vuln = TRUE;
    fix = "4.6.6";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

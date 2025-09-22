# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108239");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-09-11 08:48:02 +0200 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2643", "CVE-2011-2718");
  script_name("phpMyAdmin 3.4.x < 3.4.3.2 Multiple Directory Traversal Vulnerabilities (PMASA-2011-10, PMASA-2011-11) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2011-10/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48874");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2011-11/");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 3.4.x before 3.4.3.2.");

  script_tag(name:"solution", value:"Update to version 3.4.3.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^3\.4\." ) {
  if( version_is_less( version:vers, test_version:"3.4.3.2" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.4.3.2" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

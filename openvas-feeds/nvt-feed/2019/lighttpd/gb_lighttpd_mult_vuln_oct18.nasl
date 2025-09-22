# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108550");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-02-19 10:42:10 +0100 (Tue, 19 Feb 2019)");
  script_cve_id("CVE-2018-25103");
  script_name("Lighttpd < 1.4.51 Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("sw_lighttpd_http_detect.nasl");
  script_mandatory_keys("lighttpd/detected");

  script_xref(name:"URL", value:"https://www.lighttpd.net/2018/10/14/1.4.51/");
  script_xref(name:"URL", value:"https://www.runzero.com/blog/lighttpd/");

  script_tag(name:"summary", value:"Lighttpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-25103: There is an information leak due to a string comparison against a stale
  pointer.

  - directory traversal attack in the mod_userdir module");

  script_tag(name:"affected", value:"Lighttpd versions before 1.4.51.");

  script_tag(name:"solution", value:"Update to version 1.4.51 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.4.51" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.51" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

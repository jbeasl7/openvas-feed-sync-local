# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:allegrosoft:rompager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105154");
  script_cve_id("CVE-2014-9222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-27T05:05:08+0000");

  script_name("Allegro RomPager `Misfortune Cookie` Vulnerability");

  script_xref(name:"URL", value:"http://mis.fortunecook.ie/");
  script_xref(name:"URL", value:"http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request with a special crafted cookie and check the response.");

  script_tag(name:"solution", value:"Firmware update is available.");

  script_tag(name:"summary", value:"The remote Allegro RomPager service is vulnerable to the `Misfortune Cookie` Vulnerability.");

  script_tag(name:"affected", value:"RomPager services with versions before 4.34");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-23 10:22:44 +0100 (Tue, 23 Dec 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_allegro_rompager_detect.nasl");
  script_require_ports("Services/www", 7547);
  script_mandatory_keys("allegro/rompager/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

vtstrings = get_vt_strings();
url = '/tr069';
rand = '/' + vtstrings["lowercase_rand"];
cookie = 'C107373883=' + rand;

if( http_vuln_check( port:port, url:url, pattern:rand, extra_check:'was not found on the RomPager', cookie:cookie ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

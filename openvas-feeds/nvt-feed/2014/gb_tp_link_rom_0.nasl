# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103886");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");

  script_name("Multiple Routers 'rom-0' Vulnerability");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/01/20/tp-link-td-w8901g-router-multiple-vulnerabilities/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60682");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-21 12:05:08 +0100 (Tue, 21 Jan 2014)");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security
  restrictions and obtain sensitive information which may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Request /rom-0 and check the response.");

  script_tag(name:"insight", value:"If you request the /rom-0 file it does not require
  authentication. This can be reversed using available tools zynos.php. The first string returned is the
  admin password.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"The remote Router is prone to the 'rom-0' Vulnerability.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
if( "Server: RomPager/" >!< banner ) exit (0);

req = http_get( item:'/rom-0', port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "dbgarea" >< buf && "spt.dat" >< buf )
{
  security_message( port:port );
  exit(0);
}

exit(99);

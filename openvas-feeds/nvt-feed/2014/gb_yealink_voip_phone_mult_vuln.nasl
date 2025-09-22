# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804468");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2013-5755", "CVE-2013-5756", "CVE-2013-5757", "CVE-2013-5758",
                "CVE-2013-5759");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-20 12:14:02 +0530 (Fri, 20 Jun 2014)");
  script_name("Yealink VoIP Phone SIP-T38G Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Yealink VoIP Phone devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted default credential via HTTP GET request and check whether it
  is able to login or not.");

  script_tag(name:"insight", value:"- The 'user' account has a password of 'user' (hash = s7C9Cx.rLsWFA), the
  'admin' account has a password of 'admin' (hash = uoCbM.VEiKQto), and
  the 'var' account has a password of 'var' (hash = jhl3iZAe./qXM).

  - The '/cgi-bin/cgiServer.exx' script not properly sanitizing user input,
  specifically encoded path traversal style attacks (e.g. '%2F') supplied
  via the 'page' parameter.

  - Contains a flaw in the /cgi-bin/cgiServer.exx script that is triggered
  when handling system calls.

  - The /cgi-bin/cgiServer.exx script not properly sanitizing user input,
  specifically absolute paths supplied via the 'command' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially gain privileged
  access to the device, execute arbitrary commands and gain access to arbitrary files.");

  script_tag(name:"affected", value:"Yealink VoIP Phone SIP-T38G");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68054");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33741");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33740");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33739");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SIP-T38G/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

kPort = http_get_port(default:80);

kBanner = http_get_remote_headers(port: kPort);
if('WWW-Authenticate: Basic realm="Gigabit Color IP Phone SIP-T38G"' >!< kBanner) exit(0);

host = http_host_name(port:kPort);

credentials = make_list("user:user", "admin:admin", "var:var");
foreach credential ( credentials )
{
  userpass = base64( str:credential );
  sipReq = 'GET / HTTP/1.1\r\n' +
           'Host: ' +  host + '\r\n' +
           'Authorization: Basic ' + userpass + '\r\n' +
           '\r\n';

  sipRes = http_keepalive_send_recv( port:kPort, data:sipReq, bodyonly:FALSE );

  if(sipRes =~ "^HTTP/1\.[01] 200"  && "<title>IP Phone<" >< sipRes){
    defaults = defaults + credential + '\n';
  }
}

if(defaults)
{
  defaults = str_replace( string:defaults, find:":", replace:"/" );
  report = 'It was possible to login using the following credentials:\n\n' + defaults;
  security_message(port:kPort, data:report );
  exit(0);
}

exit(99);

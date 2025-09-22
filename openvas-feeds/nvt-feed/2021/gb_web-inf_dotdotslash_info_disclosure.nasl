# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117221");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2004-0281");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-02-11 15:27:45 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("'/WEB-INF../' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=107635084830547&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9617");

  script_tag(name:"summary", value:"Various application or web servers / products are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Caucho Resin version 2.1.12 on Apache HTTP server version 1.3.29

  Other products and versions might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from
  serving resources in the '/WEB-INF' and '/META-INF' directories of a web application archive
  directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that exposes this
  information if the client requests a URL like this instead:

  http://example.com/WEB-INF../web.xml

  http://example.com/web-inf../web.xml

  (note the double dot ('..') after 'WEB-INF').");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might
  be able to gather additional info and / or sensitive data about the application / the application
  / web server.");

  script_tag(name:"solution", value:"Please contact the vendor for more information on possible fixes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: resin-web.xml for Caucho Resin is separately tested in common/2023/caucho/gb_resin_CVE-2004-0281_active.nasl

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

base_pattern  = "^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)";
extra_pattern = "^\s*</(web-app|servlet(-mapping)?)>$";

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/WEB-INF/web.xml";
  res = http_get_cache( item:url, port:port );

  # nb: Avoid excessive reporting if the file is directly accessible (already checked by
  # 2018/gb_sensitive_file_disclosures_http.nasl and 2021/gb_web-inf_plain_info_disclosure.nasl).
  if( res &&
      egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) )
    continue;

  url = dir + "/WEB-INF../web.xml";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( res &&
      egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }

  # We want to check the lowercase variant as well.
  url = str_replace( string:url, find:"/WEB-INF../web.xml", replace:"/web-inf../web.xml" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  if( egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

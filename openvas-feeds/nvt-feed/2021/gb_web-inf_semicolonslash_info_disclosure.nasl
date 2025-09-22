# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117708");
  script_version("2025-01-21T05:37:33+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-26085", "CVE-2021-26086", "CVE-2021-44138", "CVE-2022-31656");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-10-06 10:19:53 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 16:02:00 +0000 (Thu, 11 Aug 2022)");
  script_name("'/;/WEB-INF/' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/JRASERVER-72695");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CONFSERVER-67893");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/164405/Atlassian-Jira-Server-Data-Center-8.4.0-File-Read.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/164401/Atlassian-Confluence-Server-7.5.1-Arbitrary-File-Read.html");
  script_xref(name:"URL", value:"https://github.com/maybe-why-not/reponame/issues/2");

  script_tag(name:"summary", value:"Various application or web servers / products are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - CVE-2021-26085: Atlassian Confluence

  - CVE-2021-26086: Atlassian Jira Server

  - CVE-2021-44138: Caucho Resin version 4.0.52 through 4.0.56

  - CVE-2022-31656: VMware Workspace ONE Access, Identity Manager and Realize Automation

  Other products might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from
  serving resources in the '/WEB-INF' and '/META-INF' directories of a web application archive
  directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that exposes this
  information if the client requests a URL like this instead:

  http://example.com/<semicolon>/WEB-INF/web.xml

  http://example.com/<semicolon>/web-inf/web.xml

  (note the '<semicolon>/' before 'WEB-INF').");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might
  be able to gather additional info and/or sensitive data about the application / the application /
  web server.");

  script_tag(name:"solution", value:"The following vendor fixes are known:

  - Update Atlassian Confluence to the latest available version

  - Update Atlassian Jira Server to the latest available version

  - Update Caucho Resin to the latest available version

  For other products please contact the vendor for more information on possible fixes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: resin-web.xml for Caucho Resin is separately tested in common/2023/caucho/gb_resin_path_trav_vuln_apr22_active.nasl

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

base_pattern  = "^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)";
extra_pattern = "^\s*</(web-app|servlet(-mapping)?)>$";

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/",
                               "/s/test/_", # nb: Atlassian Jira Server and Atlassian Confluence
                               "/SAAS/t/_", # nb: CVE-2022-31656
                               http_cgi_dirs( port:port ) ) ) {

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

  url = str_replace( string:url, find:"/WEB-INF/web.xml", replace:"/;/WEB-INF/web.xml" );

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

  # nb: We also want to check the lowercase variant...
  url = str_replace( string:url, find:"/WEB-INF/web.xml", replace:"/web-inf/web.xml" );

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

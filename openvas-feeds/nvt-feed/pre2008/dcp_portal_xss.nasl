# SPDX-FileCopyrightText: 2003 k-otik.com
# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11446");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1536", "CVE-2004-2511", "CVE-2004-2512");
  script_xref(name:"OSVDB", value:"10585");
  script_xref(name:"OSVDB", value:"10586");
  script_xref(name:"OSVDB", value:"10587");
  script_xref(name:"OSVDB", value:"10588");
  script_xref(name:"OSVDB", value:"10589");
  script_xref(name:"OSVDB", value:"10590");
  script_xref(name:"OSVDB", value:"11405");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("DCP-Portal <= 5.3.2 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2003 k-otik.com & Copyright (C) 2004 David Maciejak");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20070807182316/http://archives.neohapsis.com/archives/bugtraq/2004-10/0042.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20070807171958/http://archives.neohapsis.com/archives/fulldisclosure/2004-10/0131.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162429/http://www.securityfocus.com/bid/11338");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162429/http://www.securityfocus.com/bid/11339");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162429/http://www.securityfocus.com/bid/11340");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162429/http://www.securityfocus.com/bid/7141");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162429/http://www.securityfocus.com/bid/7144");

  script_tag(name:"summary", value:"DCP-Portal is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Cross-site scripting (XSS) flaws in calendar.php script, which may let an attacker to execute
  arbitrary code in the browser of a legitimate user.

  In addition to this, the product may also be vulnerable to:

  - HTML injection flaws, which may let an attacker to inject hostile HTML and script code that
  could permit cookie-based credentials to be stolen and other attacks.

  - HTTP response splitting flaw, which may let an attacker to influence or misrepresent how web
  content is served, cached or interpreted.");

  script_tag(name:"affected", value:"DCP-Portal version 5.3.2 and prior is known to be affected.
  Newer versions might be affected as well.");

  script_tag(name:"solution", value:"Update to a newer version when available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/calendar.php", port:port );

  # Detection pattern has been extracted from here:
  # - https://web.archive.org/web/20041211215541/http://www.dcp-portal.org/calendar.php
  # - https://web.archive.org/web/20030608062912/http://www.dcp-portal.org/calendar.php
  # - https://web.archive.org/web/20030216041305/http://www.dcp-portal.org/calendar.php
  #
  # Powered by <a class="sublinks" href="http://www.dcp-portal.com/" target="_blank">DCP-Portal v6.0 SE</a></font></td>
  #
  # <td class="p2"><font color="#FFFFFF" size="1">Powered by <a href="http://www.dcp-portal.com/" target="_blank" class="white">DCP-Portal
  #    v5.4 SE</a></font></td>
  #
  # <td class="p2"><font color="#FFFFFF" size="1">Powered by <a href="http://www.dcp-portal.com/" target="_blank" class="white">DCP-Portal
  #    v5.2 SE</a></font></td>
  #
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "(dcp-portal\.(com|org)|>DCP-Portal|calendar\.php\?(year|month|day))" )
    continue;

  url = string( dir, "/calendar.php?year=2004&month=<script>foo</script>&day=01" );

  if( http_vuln_check( port:port, url:url, pattern:"<script>foo</script>", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

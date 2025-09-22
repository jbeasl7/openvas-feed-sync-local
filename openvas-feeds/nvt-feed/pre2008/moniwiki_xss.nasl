# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15566");
  script_version("2024-06-19T05:05:42+0000");
  script_cve_id("CVE-2004-1632");
  script_tag(name:"last_modification", value:"2024-06-19 05:05:42 +0000 (Wed, 19 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("MoniWiki < 1.0.9 XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162529/http://www.securityfocus.com/bid/11516");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=109873622006103&w=2");

  script_tag(name:"summary", value:"MoniWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The remote version of this software is vulnerable to XSS
  attacks, through the script 'wiki.php'.

  With a specially crafted URL, an attacker can cause arbitrary code execution in users' browsers
  resulting in a loss of integrity.");

  script_tag(name:"affected", value:"MoniWiki version 1.0.8 and prior.");

  script_tag(name:"solution", value:"Update to version 1.0.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(dont_add_port:TRUE);
if(http_get_has_generic_xss(port:port, host:host))
  exit(0);

foreach dir(make_list_unique("/moniwiki", "/MoniWiki", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/wiki.php", port:port);
  if(!res || res !~ "^HTTP/1\.[01] 200" || res !~ "(powered by MoniWiki|<wikiHeader>)")
    continue;

  url = dir + "/wiki.php/<script>foo</script>";
  if(http_vuln_check(port:port, url:url, pattern:"<wikiHeader>", extra_check:"<script>foo</script>", check_header:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

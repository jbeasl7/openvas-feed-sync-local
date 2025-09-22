# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15451");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1588", "CVE-2004-1589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11361");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("GoSmart Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");

  script_tag(name:"summary", value:"GoSmart is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The remote version of this software contains multiple flaws, due
  to a failure of the application to properly sanitize user-supplied input. It is also affected by a
  cross-site scripting vulnerability. As a result of this vulnerability, it is possible for a remote
  attacker to create a malicious link containing script code that will be executed in the browser of
  an unsuspecting user when followed. Furthermore, this version is vulnerable to SQL injection flaws
  that let an attacker inject arbitrary SQL commands.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if ( ! http_can_host_asp(port:port) ) exit(0);
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/messageboard", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = string(dir, "/Forum.asp?QuestionNumber=1&Find=1&Category=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E%3C%22");
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( isnull( r ) ) continue;

  if (r =~ "^HTTP/1\.[01] 200" && egrep(pattern:"<script>foo</script>", string:r)) {
    security_message(port);
    exit(0);
  }
}

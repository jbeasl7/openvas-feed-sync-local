# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cutephp:cutenews";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14318");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0660");
  script_xref(name:"OSVDB", value:"8833");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CuteNews < 1.3.2 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("cutenews_detect.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("cutenews/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/12260/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10948");

  script_tag(name:"summary", value:"CuteNews is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The version of CuteNews on the remote host fails to sanitize
  input to the 'archive' parameter of the 'show_archives.php' script. An attacker, exploiting this
  flaw, would need to be able to coerce a user to browse to a purposefully malicious URI. Upon
  successful exploitation, the attacker would be able to run code within the web-browser in the
  security context of the CuteNews server.");

  script_tag(name:"solution", value:"Update to version 1.3.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(dont_add_port:TRUE);
if(http_get_has_generic_xss(port:port, host:host))
  exit(0);

url = dir + "/show_archives.php?archive=<script>foo</script>&subaction=list-archive&";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if(res =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

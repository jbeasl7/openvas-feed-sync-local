# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: Javier Ubilla and Ariel

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14257");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10884");
  script_xref(name:"OSVDB", value:"8383");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Moodle post.php XSS");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_moodle_cms_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Moodle/Version");

  script_tag(name:"solution", value:"Upgrade to Moodle 1.4 or newer.");

  script_tag(name:"summary", value:"The version of Moodle on the remote host contains a flaw that allows a
  remote cross site scripting attack because the application does not validate the 'reply' variable upon
  submission to the 'post.php' script.");

  script_tag(name:"impact", value:"This could allow a user to create a specially crafted URL that would
  execute arbitrary code in a user's browser within the trust relationship between the browser and the
  server, leading to a loss of integrity.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  req = http_get(item:string(dir, "/post.php?reply=<script>document.write('VT to detect post.php flaw');</script>"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( isnull( res ) ) exit( 0 );

  if (res =~ "^HTTP/1\.[01] 200" && ereg(pattern:"VT plugin to detect post.php flaw", string:res ))
  {
    security_message(port);
    exit(0);
  }
}

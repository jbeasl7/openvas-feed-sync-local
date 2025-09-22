# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11914");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-2389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5250");
  script_name("TheServer clear text password");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Remote file access");
  script_dependencies("gb_theserver_detect.nasl", "no404.nasl");
  script_mandatory_keys("theserver/detected");

  script_tag(name:"solution", value:"Upgrade your software or reconfigure it.");

  script_tag(name:"summary", value:"We were able to read the server.ini file It may contain sensitive
  information like clear text passwords. This flaw is known to affect TheServer.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

CPE = "cpe:/a:fastlink_software:theserver";

include("host_details.inc");
include("http_func.inc");
include("http_404.inc");
include("misc_func.inc");

function testfile(port, no404, f)
{
  local_var req, h, b, soc;

  soc = http_open_socket(port);
  if (!soc) return 0;
  req = http_get(port: port, item: f);
  send(socket: soc, data: req);
  h = http_recv_headers2(socket: soc);
  b = http_recv_body(socket: soc, headers: h);
  http_close_socket(soc);

  if (h =~ '^HTTP/[0-9.]+ +2[0-9][0-9]' && b)
  {
    if (! no404 || no404 >!< b)
      return 1;
  }
  return 0;
  #if (egrep(string: b, pattern: "^ *password *=")) ...
}

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

host = http_host_name(dont_add_port: TRUE);
no404 = http_get_no404_string(port: port, host: host);

if(testfile(port: port, no404: no404, f: "/" + rand_str() + ".ini"))
  exit(99);

if(testfile(port: port, no404: no404, f: "/server.ini")) {
  report = http_report_vuln_url(port: port, url: "/server.ini");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

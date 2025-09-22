# SPDX-FileCopyrightText: 2006 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:neocrome:land_down_under";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19603");
  script_version("2024-08-06T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-08-06 05:05:45 +0000 (Tue, 06 Aug 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2674", "CVE-2005-2675", "CVE-2005-2788", "CVE-2005-2884",
                "CVE-2005-4821");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Land Down Under <= 801 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("ldu_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ldu/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210120153150/https://www.securityfocus.com/archive/1/409511");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121164400/http://www.securityfocus.com/bid/14685");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121164400/http://www.securityfocus.com/bid/14746");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121164400/http://www.securityfocus.com/bid/14820");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0509-advisories/LDU801.txt");

  script_tag(name:"summary", value:"Land Down Under is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2005-2788, CVE-2005-2884, CVE-2005-4821: The remote version of Land Down Under is prone to
  several SQL injection (SQLi) and cross-site scripting (XSS) attacks due to its failure to sanitize
  user-supplied input to several parameters used by the 'events.php', 'index.php', and 'list.php'
  scripts. A malicious user can exploit these flaws to manipulate SQL queries, steal authentication
  cookies, and the like

  Furthermore version 800 also contains the following flaws:

  - CVE-2005-2674: Multiple XSS vulnerabilities

  - CVE-2005-2675: Multiple SQLi vulnerabilities

  Note: The vendor has disputed these two CVEs but the origin / proof is unknown and the CVEs still
  have been added for archiving / tracking purposes.");

  script_tag(name:"affected", value:"Land Down Under versions 801 and prior are known to be
  affected. Newer versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/list.php?c='&s=title&w=asc&o=vuln-test&p=1";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if ("MySQL error" >< res && egrep(string:res, pattern:"syntax to use near '(asc&o=|0.+page_vuln-test)")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

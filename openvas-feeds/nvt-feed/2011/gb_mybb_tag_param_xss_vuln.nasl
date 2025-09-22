# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902804");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-12-27 15:15:15 +0530 (Tue, 27 Dec 2011)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MyBB 'tags.php' XSS Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mybb/http/detected");

  script_tag(name:"summary", value:"MyBB is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'tag' parameter in 'tags.php', which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"MyBB versions 1.6.5 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45388");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64148");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108156/mybb165-xss.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96658/mybbtag-xss.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/tags.php?tag="><script>alert(document.cookie)</script>';

if (http_vuln_check(port:port, url:url, check_header: TRUE,
                   pattern:"><script>alert\(document.cookie\)</script>")) {
  report  = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

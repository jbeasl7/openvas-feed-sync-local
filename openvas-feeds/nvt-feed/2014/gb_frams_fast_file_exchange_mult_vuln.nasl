# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804664");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2014-3876", "CVE-2014-3877", "CVE-2014-3875");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-06 17:24:00 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2014-07-04 10:06:54 +0530 (Fri, 04 Jul 2014)");
  script_name("Frams&qt Fast File EXchange Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Frams&qt Fast File EXchange is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is possible to
  read a given string.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An input passed via the 'akey' parameter to /rup is not properly sanitised before
  being returned to the user.

  - An input passed via the 'addto' parameter to /fup is not properly sanitised
  before being returned to the user.

  - An input passed via the 'disclaimer' and 'gm' parameters to /fuc is not properly
  sanitised before being returned to the user.

  - Application allows users to perform certain actions via HTTP requests without
  performing proper validity checks to verify the requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct HTTP response splitting,
  conduct request forgery attacks and execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Frams&qt Fast File EXchange before version 20140526");

  script_tag(name:"solution", value:"Upgrade to Frams&qt Fast File EXchange version 20140526 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58486");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67785");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67788");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q2/405");
  script_xref(name:"URL", value:"http://fex.rus.uni-stuttgart.de/fex.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126906");
  script_xref(name:"URL", value:"https://www.lsexperts.de/advisories/lse-2014-05-22.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("fexsrv/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

fexPort = http_get_port(default:8080);

banner = http_get_remote_headers(port:fexPort);
if(!banner || "Server: fexsrv" >!< banner) exit(0);

url = "/rup?akey=foo%22%20onmouseover=alert%28%22XSS-test%22%29%20bar=%22";

if(http_vuln_check(port:fexPort, url:url, check_header:TRUE,
                   pattern:'onmouseover=alert.*XSS-test.*bar',
                   extra_check: make_list('F*EX operation control<', 'F*EX redirect<'))){
  report = http_report_vuln_url( port:fexPort, url:url );
  security_message(port:fexPort, data:report);
  exit(0);
}

exit(99);

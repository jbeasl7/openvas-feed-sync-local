# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10852");
  script_version("2024-06-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-06-05 05:05:26 +0000 (Wed, 05 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0565");
  script_name("Oracle 9iAS Jsp Source File Reading Information Disclosure Vulnerability - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20080820021515/http://www.nextgenss.com/advisories/orajsa.txt");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210129085734/http://www.securityfocus.com/bid/4034/");

  script_tag(name:"summary", value:"In a default installation of Oracle 9iAS it is possible to read
  the source of JSP files.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"When a JSP is requested it is compiled 'on the fly' and the
  resulting HTML page is returned to the user. Oracle 9iAS uses a folder to hold the intermediate
  files during compilation. These files are created in the same folder in which the .JSP page
  resides.

  Hence, it is possible to access the .java and compiled .class files for a given JSP page.");

  script_tag(name:"solution", value:"Edit httpd.conf to disallow access to the _pages folder.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# This plugin uses a demo jsp to test for this vulnerability. It would be
# better to use the output of webmirror.nasl to find valid .jsp pages
# which could then be used in the test. In situations where the demo pages
# have been removed this plugin will false negative.

req = http_get(item:"/demo/ojspext/events/index.jsp", port:port);
res = http_send_recv(port:port, data:req);
if(res && "This page has been accessed" >< res) {

  url = "/demo/ojspext/events/_pages/_demo/_ojspext/_events/_index.java";
  req = http_get(item:url, port:port);
  res = http_send_recv(port:port, data:req);
  if(res && "import oracle.jsp.runtime.*" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);

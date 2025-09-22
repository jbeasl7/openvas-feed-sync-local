# SPDX-FileCopyrightText: 2001 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:jrun";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10996");
  script_version("2024-06-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-06-05 05:05:26 +0000 (Wed, 05 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2000-0539", "CVE-2000-0540");
  script_name("Allaire/Macromedia JRun Sample Files (HTTP) - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Digital Defense Inc.");
  script_family("Web Servers");
  script_dependencies("gb_adobe_jrun_http_detect.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("adobe/jrun/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210222083034/http://www.securityfocus.com/bid/1386");

  script_tag(name:"summary", value:"This host is running the Allaire JRun web server and has sample
  files installed.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"impact", value:"Several of the sample files that come with JRun contain serious
  security flaws. An attacker can use these scripts to relay web requests from this machine to
  another one or view sensitive configuration information.");

  script_tag(name:"solution", value:"Sample files should never be left on production servers. Remove
  the sample files and any other files that are not required.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

tests = make_array(
  "/cfanywhere/index.html", "CFML Sample",
  "/docs/servlets/index.html", "JRun Servlet Engine",
  "/jsp/index.html", "JRun Scripting Examples",
  "/webl/index.html", "What is WebL"
);

foreach url(keys(tests)) {

  check = tests[url];

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(data:req, port:port);
  if(!res)
    continue;

  if(check >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

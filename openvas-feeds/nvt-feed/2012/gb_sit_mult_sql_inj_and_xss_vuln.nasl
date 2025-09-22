# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sitracker:support_incident_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802388");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-02-01 15:15:30 +0530 (Wed, 01 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-5071", "CVE-2011-5072", "CVE-2011-5073", "CVE-2011-5074",
                "CVE-2011-5075");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Support Incident Tracker SiT! < 3.65 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_support_incident_tracker_http_detect.nasl");
  script_mandatory_keys("sit/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Support Incident Tracker is prone to multiple SQL injection
  (SQLi) and cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to improper input validation errors in
  multiple scripts before being used in SQL queries and also allows attackers to execute arbitrary
  HTML.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable site and to cause
  SQL Injection attack to gain sensitive information.");

  script_tag(name:"affected", value:"Support Incident Tracker prior to version 3.65.");

  script_tag(name:"solution", value:"Update to version 3.65 or later.");

  script_xref(name:"URL", value:"http://sitracker.org/wiki/ReleaseNotes365");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519636");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_sit_support_incident_tracker.html");

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

url = dir + "/forgotpwd.php?userid=1&action=sendpwd";

headers = make_array("Authorization", "Basic bGFtcHA6",
                     "Referer", "<script>alert(document.cookie);</script>");

req = http_get_req(port: port, url: port, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (ereg(pattern: "^HTTP/[0-9]\.[0-9] 200 .*", string: res) &&
    "<script>alert(document.cookie);</script>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

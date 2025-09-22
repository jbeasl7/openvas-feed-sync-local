# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810730");
  script_version("2024-05-24T19:38:34+0000");
  script_cve_id("CVE-2016-6816");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 22:15:00 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-04-04 14:36:33 +0530 (Tue, 04 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Apache Tomcat HTTP Request Line Information Disclosure Vulnerability (CVE-2016-6816) - Active Check");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The code that parsed the HTTP request line
  permitted invalid characters. This could be exploited, in conjunction with a
  proxy that also permitted the invalid characters but with a different
  interpretation, to inject data into the HTTP response.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to poison a web-cache, perform an XSS attack and/or obtain sensitive
  information from requests other then their own.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 through 9.0.0.M11, 8.5.0
  through 8.5.6, 8.0.0.RC1 through 8.0.38, 7.0.0 through 7.0.72 and 6.0.0 through 6.0.47.");

  script_tag(name:"solution", value:"Update to version 9.0.0.M13, 8.5.8, 8.0.39, 7.0.73, 6.0.48 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.48");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94461");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.73");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.39");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.8");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M13");
  script_xref(name:"URL", value:"https://qnalist.com/questions/7885204/security-cve-2016-6816-apache-tomcat-information-disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/http/detected");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/?{{%25}}cake\=1";

## Response will be Apache tomcat front page something like
## https://en.wikipedia.org/wiki/File:Apache-tomcat-frontpage-epiphany-browser.jpg
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"Apache Software Foundation", extra_check:make_list("tomcat\.apache\.org<",
           '"Powered by Tomcat"', "tomcat\.gif", "tomcat-power\.gif"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

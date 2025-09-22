# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803980");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2005-4875");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-12-17 13:20:01 +0530 (Tue, 17 Dec 2013)");
  script_name("TYPO3 Multiple Vulnerabilities (Nov 2005)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20051114-1");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20051114-2");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20051114-4");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20051114-5");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20051114-6");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20051114-7");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple errors exist in the application:

  - An error exists in debug script which executes phpinfo() function, which makes environment
  variables world readable

  - An error exists in TYPO3 Page Cache

  - An error exists in config.baseURL, which could be used to spoof a malicious baseURL into the
  TYPO3 cache

  - An error exists in TYPO3 Install Tool, which does not generate a secure encryptionKey

  - An error exists in showpic.php, which fails to sanitize user inputs properly

  - An error exists in application, which does not forbidden access to 'fileadmin/_temp_/'
  directory");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive environment variables information or may lead to DoS.");

  script_tag(name:"affected", value:"TYPO3 versions prior to 3.8.1.");

  script_tag(name:"solution", value:"Update to version 3.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/misc/phpcheck/index.php?arg1,arg2,arg3&p1=parameter1&p2[key]=value#link1";

if(http_vuln_check(port:port, url:url, check_header:FALSE,
   pattern:"TYPO3_HOST_ONLY", extra_check:make_list("SCRIPT_FILENAME", "<title>phpinfo\(\)</title>"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

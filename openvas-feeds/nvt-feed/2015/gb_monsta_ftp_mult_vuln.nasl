# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:monsta:ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806050");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-09-15 09:23:14 +0530 (Tue, 15 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Monsta FTP Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Monsta FTP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Insufficient sanitization of user supplied input by index.php script.

  - No CSRF token exists when making some POST requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and allowing arbitrary deletion
  of files on the monstaftp server.");

  script_tag(name:"affected", value:"Monsta FTP version 1.6.2.");

  script_tag(name:"solution", value:"Upgrade to Monsta FTP version 1.6.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38148");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_monsta_ftp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Monsta-FTP-master/Installed");

  script_xref(name:"URL", value:"http://www.monstaftp.com");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/?openFolder="/><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"alert\(document.cookie\)",
   extra_check:make_list("<title>Monsta FTP", 'value="Login"')))
{
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);

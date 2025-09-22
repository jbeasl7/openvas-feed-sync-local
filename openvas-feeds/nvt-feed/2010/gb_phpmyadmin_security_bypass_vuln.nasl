# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801494");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2010-4481");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("phpMyAdmin 'phpinfo.php' Security Bypass Vulnerability - Active Check");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42485");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3238");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-10.php");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by missing authentication in the
  'phpinfo.php' script when 'PMA_MINIMUM_COMMON' is defined. This can be exploited to gain knowledge
  of sensitive information by requesting the file directly.");

  script_tag(name:"impact", value:"Successful exploitation will let the unauthenticated attackers to
  display information related to PHP.");

  script_tag(name:"affected", value:"phpMyAdmin versions prior to 3.4.0-beta1.");

  script_tag(name:"solution", value:"Update to version 3.4.0-beta1 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/phpinfo.php";

req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(">Configuration<" >< res && ">PHP Core<" >< res && ">Apache Environment<" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

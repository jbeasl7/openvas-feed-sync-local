# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803849");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-06 11:43:33 +0530 (Tue, 06 Aug 2013)");
  script_name("WordPress WPtouch Plugin Path Disclosure Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'WPtouch' is prone to path disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check whether it is able to disclose the path
or not.");
  script_tag(name:"solution", value:"Upgrade to version 1.9.8.1 or later.");
  script_tag(name:"insight", value:"Flaws is due to error in the php files in plugin folder and subfolders.");
  script_tag(name:"affected", value:"WPtouch version 1.9.7.1 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive information
like installation path.");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21071");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080037");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122687");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wptouch-wptouch-pro-xss-path-disclosure");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

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

url = dir + "/wp-content/plugins/wptouch/wptouch.php";

if(http_vuln_check(port:port, url:url,
                   pattern:"<b>Fatal error</b>: .*load_plugin_textdomain\(\) in.*wptouch.php"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

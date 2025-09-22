# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804530");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-1906", "CVE-2014-1907", "CVE-2014-1905", "CVE-2014-1908");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-04-01 12:28:38 +0530 (Tue, 01 Apr 2014)");
  script_name("WordPress VideoWhisper Live Streaming Integration Multiple Vulnerabilities");

  script_tag(name:"summary", value:"WordPress VideoWhisper Live Streaming Integration Plugin is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Improper verification of file extensions before uploading files to the server
  in '/videowhisper-live-streaming-integration/ls/vw_snapshots.php'

  - Input passed via HTTP POST parameters 'msg' to /ls/vc_chatlog.php, 'm' to
  /ls/lb_status.php, 'ct' to /ls/lb_status.php and /ls/v_status.php.

  - Input passed via HTTP GET parameters 'n' to /ls/channel.php, htmlchat.php,
  ls/video.php, and /videotext.php, 'message' to /ls/lb_logout.php, and 's'
  to rtmp_login.php and rtmp_logout.php scripts.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site and
read/delete arbitrary files.");
  script_tag(name:"affected", value:"WordPress VideoWhisper Live Streaming Integration Plugin version 4.27.3
and probably prior.");
  script_tag(name:"solution", value:"Update to version 4.29.5 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65876");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65880");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23199");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125454");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/plugins/videowhisper-live-streaming-integration");
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

url = dir + '/wp-content/plugins/videowhisper-live-streaming-integration/ls'+
            '/channel.php?n=</title><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\)</script>",
   extra_check:'>Video Whisper Live Streaming<'))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

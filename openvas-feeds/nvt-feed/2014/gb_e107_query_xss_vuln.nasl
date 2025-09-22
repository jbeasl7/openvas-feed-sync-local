# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:e107:e107";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804230");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-2750");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-28 15:46:24 +0530 (Tue, 28 Jan 2014)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("e107 query Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"e107 is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted string via HTTP GET request and check whether it is able to
inject HTML code.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'query' parameter to
'content_preset.php', which is not properly sanitised before using it.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.");

  script_tag(name:"affected", value:"e107 version 1.0.2, Other versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade e107 to version 1.0.3 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58841");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52858");

  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"remote_analysis");

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.e107.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!eport = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:eport))
  exit(0);

if (dir == "/")
  dir = "";

exploit = "<script%0d%0a>alert(12345678901)</script>";
url = dir + "/e107_plugins/content/handlers/content_preset.php?query=" + exploit;

if (http_vuln_check(port: eport, url: url, check_header:TRUE, pattern: ">alert\(12345678901\)</script>")) {
  report = http_report_vuln_url(port: eport, url: url);
  security_message(port: eport, data: report);
  exit(0);
}

exit(99);

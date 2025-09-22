# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804321");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2014-2242", "CVE-2014-2243", "CVE-2014-2244");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-03-04 10:37:52 +0530 (Tue, 04 Mar 2014)");
  script_name("Mediawiki < 1.19.12, 1.20.x < 1.21.6, 1.22.x < 1.22.3 Multiple Vulnerabilities (Mar 2014) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/57184/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65906");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65910");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/03/01/2");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Input passed via 'text' parameter to 'api.php' is not properly sanitised before being returned
  to the user.

  - Input to 'includes/upload/UploadBase.php' script is not properly sanitised during the uploading
  of an SVG namespace.

  - Error in 'includes/User.php' script in 'theloadFromSession' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site and attacker
  can gain sensitive information.");

  script_tag(name:"affected", value:"Mediawiki versions 1.19.x prior to 1.19.12, 1.20.x, 1.21.x
  prior to 1.21.6 and 1.22.x prior to 1.22.3.");

  script_tag(name:"solution", value:"Update to version 1.19.12, 1.21.6, 1.22.3 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/api.php?action=parse&text=api.php?http://onmouseover=alert%28document.cookie%29//&title=Foo&prop=wikitext&format=jsonfm";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:">http.*onmouseover=alert\(document\.cookie\)",
   extra_check:make_list(">MediaWiki API"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

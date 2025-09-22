# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804899");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-9094");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-11-28 20:20:50 +0530 (Fri, 28 Nov 2014)");
  script_name("WordPress Digital Zoom Studio (DZS) Video Gallery Plugin Multiple Vulnerabilities");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"summary", value:"WordPress Digital Zoom Studio (DZS) Video Gallery Plugin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Input passed via 'designrand'and 'swfloc'  parameters to
  dzs-videogallery/deploy/designer/preview.php script is not properly validated
  before returning it to users.

  - Direct request for the /videogallery.php and /admin/sliderexport.php scripts
  discloses the software's installation path.

  - Input passed via the 'src' parameter is not properly sanitized upon submission
  to the img.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within the
  trust relationship between their browser and the server, result in loss of
  confidentiality and execute arbitrary commands.");

  script_tag(name:"affected", value:"WordPress Digital Zoom Studio (DZS) Video
  Gallery Plugin");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126846/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68525");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jul/65");

  script_category(ACT_ATTACK);
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

url = dir + "/wp-content/plugins/dzs-videogallery/deploy/designer/"
          + 'preview.php?swfloc="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document\.cookie\)</script>",
  extra_check:">Video"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

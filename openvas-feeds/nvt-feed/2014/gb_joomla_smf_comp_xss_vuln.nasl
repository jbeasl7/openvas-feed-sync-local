# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804273");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-30 14:13:30 +0530 (Wed, 30 Apr 2014)");

  script_name("Joomla Component SMF Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Joomla! component SMF is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is possible
to read a given string.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of 'itemid' HTTP GET parameter
passed to 'index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
script code in a user's browser session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"SMF Component for Joomla");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126176");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66945");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php?option=com_smf&itemid="><marquee>XSS-TEST</marquee>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:">XSS-TEST<", extra_check:"com_smf")) {
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);

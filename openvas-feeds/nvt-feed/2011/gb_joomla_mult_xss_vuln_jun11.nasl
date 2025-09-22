# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902390");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! CMS Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48475");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/519");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary script code in
the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Joomla CMS version 1.6.3 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
'Itemid' and 'filter_order' parameters in 'index.php', before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Joomla CMS 1.6.4 or later.");

  script_tag(name:"summary", value:"Joomla is prone to multiple cross site scripting vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php?option=com_contact&view=category&catid=26&id=36&Itemid=-1";><script>alert(/XSS-Test' +
      'ing/)</script>';

if (http_vuln_check(port: port, url: url, pattern: ';><script>alert(/XSS-Testing/)</script>',
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

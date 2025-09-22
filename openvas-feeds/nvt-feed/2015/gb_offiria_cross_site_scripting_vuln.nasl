# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:slashes&dots:offria";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805191");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-2689");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-27 16:23:32 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Offiria Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Offiria is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to insufficient sanitization
  of user-supplied data in URI after '/installer/index.php' script is not
  removed from the system by default.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"Offiria version 2.1.1 and probably prior.");

  script_tag(name:"solution", value:"As a workaround remove the vulnerable
  script or restrict access to it via .htaccess file or WAF.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/532048");
  script_xref(name:"URL", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2689.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_offiria_remote_detect.nasl");
  script_mandatory_keys("offiria/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://offiria.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appDir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = appDir + '/installer/index.php/"onmouseover="alert(document.cookie) ;"=">';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"alert\(document.cookie\)", extra_check:">Offiria Installation<"))
{
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

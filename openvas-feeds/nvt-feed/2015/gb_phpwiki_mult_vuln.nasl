# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpwiki:phpwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806034");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-09-02 11:34:10 +0530 (Wed, 02 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("PhpWiki Multiple Vulnerabilities");

  script_tag(name:"summary", value:"PhpWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flwas are due,

  - An improper inpuit sanitization of GET or POST 'pagename' parameter in
   'user preferences'.

  - An improper inpuit sanitization of GET or POST 'source' parameter in
   'file load section'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session, read
  arbitrary files and to trigger specific actions.");

  script_tag(name:"affected", value:"PhpWiki version 1.5.4");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38027");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133382");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpwiki_detect.nasl");
  script_mandatory_keys("PhpWiki/Installed");
  script_require_ports("Services/www", 80);
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

url = dir + '/index.php?pagename=%3C%2Fscript%3E%3Cscript%3Ealert%28document' +
            '.cookie%29%3C%2Fscript%3E%3C!--';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script",
   extra_check:"PhpWiki"))
{
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801660");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4480");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpMyAdmin 'error.php' Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15699/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3133");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
HTML code within the error page and conduct phishing attacks.");
  script_tag(name:"affected", value:"phpMyAdmin version 3.3.8.1 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by input validation errors in the 'error.php'
script when processing crafted BBcode tags containing '@' characters, which
could allow attackers to inject arbitrary HTML code within the error page
and conduct phishing attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

vt_strings = get_vt_strings();

url = string(dir,"/error.php?type=",vt_strings["default"],"&error=Attack+via+",
                 "characters+injection+-+[a%40http://www.",vt_strings["lowercase"],".org%40_self]",
                 "This%20Is%20a%20Link[%2Fa]");

if(http_vuln_check(port:port, url:url, pattern:'<h1>phpMyAdmin - ' + vt_strings["default"] + '</h1>',
                   extra_check: make_list('Attack via characters injection',
                   '<a href="http://www.'+ vt_strings["lowercase"] +'.org" target="_self">This Is a Link</a>')))
{
  security_message(port);
  exit(0);
}

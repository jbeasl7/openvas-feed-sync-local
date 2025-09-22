# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:iball:baton_150m_wireless-n_router";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811313");
  script_version("2025-03-26T05:38:58+0000");
  script_cve_id("CVE-2017-6558", "CVE-2017-14244");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 18:27:00 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2017-08-31 12:06:39 +0530 (Thu, 31 Aug 2017)");
  script_name("iBall Baton 150M Wireless Router Authentication Bypass Vulnerability - Active Check");

  script_tag(name:"summary", value:"iBall Baton 150M Wireless Router devices are prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get specific information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - iball Baton 150M Router login page is insecurely developed and any attacker
    could bypass the admin authentication just by tweaking the password.cgi file.

  - iBall ADSL2+ Home Router does not properly authenticate when pages are
    accessed through cgi version.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to bypass authentication mechanism and perform
  unauthorized actions and can access sensitive information and perform actions
  such as reset router, downloading backup configuration, upload backup etc.
  This may lead to further attacks.");

  script_tag(name:"affected", value:"- iBall Baton 150M Wireless-N ADSI.2+ Router 1.2.6 build 110401

  - iBall ADSL2+ Home Router WRA150N Firmware version FW_iB-LR7011A_1.0.2

  Other devices might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96822");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42740");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/22");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_iball_baton_150m_wireless_router_detect.nasl");
  script_mandatory_keys("iBall_Baton_150M_Router/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/password.cgi";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && ">Access Control -- Password<" >< res &&
   "Access to your DSL router" >< res && "pwdAdmin =" >< res &&
   "pwdSupport =" >< res && "pwdUser =" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

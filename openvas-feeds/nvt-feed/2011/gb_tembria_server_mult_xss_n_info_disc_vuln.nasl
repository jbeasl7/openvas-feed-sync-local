# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902479");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3684", "CVE-2011-3685");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Tembria Server Multiple Cross-Site Scripting and Information Disclosure Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Feb/176");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46384");
  script_xref(name:"URL", value:"http://www.solutionary.com/index/SERT/Vuln-Disclosures/Tembria-Server-Monitor-XSS.html");
  script_xref(name:"URL", value:"http://www.solutionary.com/index/SERT/Vuln-Disclosures/Tembria-Server-Monitor-Weak-Xpto-Pwd-Storage.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_tembria_server_monitor_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("tembria/server_monitor/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain the sensitive
  information about the user, session, and application and using XSS, an
  attacker could insert malicious code into a web page and entice users to
  execute the  malicious code.");

  script_tag(name:"affected", value:"Tembria Server Monitor Version 6.0.4 Build 2229 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the Web application management interface, which allows for
    execution of Cross-site Scripting (XSS) attacks.

  - An error in Tembria Server Monitor application allowing an attacker to
    easily decrypt usernames and passwords used to authenticate to the
    application.");

  script_tag(name:"solution", value:"Upgrade Tembria Server Monitor version 6.0.5 Build 2252 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Tembria Server Monitor is prone to cross-site scripting and information disclosure vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:8080);

tembriaVer = get_version_from_kb(port:port, app:"tembria");
if(tembriaVer)
{
   if(version_is_less(version:tembriaVer, test_version:"6.0.5.2252")){
     report = report_fixed_ver(installed_version:tembriaVer, fixed_version:"6.0.5.2252");
     security_message(port:port, data:report);
   }
}

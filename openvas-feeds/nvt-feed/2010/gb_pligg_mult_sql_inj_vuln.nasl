# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801258");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2010-2577", "CVE-2010-3013");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_name("Pligg Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42408");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-111/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("pligg_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pligg/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"Pligg CMS Version 1.1.0 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied inputs via the
  'title' parameter in storyrss.php and story.php and 'role' parameter in
  groupadmin.php that allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Pligg CMS Version 1.1.1 or later.");

  script_tag(name:"summary", value:"Pligg CMS is prone to multiple SQL injection vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(ver = get_version_from_kb(port:port, app:"pligg"))
{
  if(version_is_less(version:ver, test_version:"1.1.1")){
    report = report_fixed_ver(installed_version:ver, fixed_version:"1.1.1");
    security_message(port: port, data: report);
  }
}

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800992");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0726");
  script_name("tDiary 'tb-send.rb' Plugin Cross-Site Scripting Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tdiary_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tdiary/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"tDiary versions prior to 2.2.3.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of the 'plugin_tb_url' and
  'plugin_tb_excerpt' parameters upon submission to the tb-send.rb plugin script.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 2.2.3 or later.");

  script_tag(name:"summary", value:"tDiary is prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://www.tdiary.org/20100225.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38413");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38742");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2010/JVNDB-2010-000005.html");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

diaryPort = http_get_port(default:80);

diaryVer = get_kb_item("www/" + diaryPort + "/tdiary");
if(isnull(diaryVer))
  exit(0);

diaryVer = eregmatch(pattern:"^(.+) under (/.*)$", string:diaryVer);
if(diaryVer[1] != NULL)
{
  if(version_is_less(version:diaryVer[1], test_version:"2.2.3")){
    report = report_fixed_ver(installed_version:diaryVer[1], fixed_version:"2.2.3");
    security_message(port:diaryPort, data:report);
  }
}


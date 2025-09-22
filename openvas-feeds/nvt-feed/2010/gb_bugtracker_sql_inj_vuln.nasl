# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801279");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-3188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BugTracker.NET 'search.aspx' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42784");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61434");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513385/100/0/threaded");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/btnet/files/btnet_3_4_4_release_notes.txt/view");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bugtracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BugTrackerNET/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"BugTracker.NET version 3.4.3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  custom field parameters to 'search.aspx' that allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to BugTracker.NET version 3.4.4 or later.");

  script_tag(name:"summary", value:"BugTracker.NET is prone to an SQL injection (SQLi) vulnerability.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(ver = get_version_from_kb(port:port, app:"btnet"))
{
  if(version_is_less(version:ver, test_version: "3.4.3")){
      report = report_fixed_ver(installed_version:ver, fixed_version:"3.4.3");
      security_message(port: port, data: report);
  }
}

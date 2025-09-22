# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902407");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_cve_id("CVE-2010-3266", "CVE-2010-3267");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("BugTracker.NET Cross-Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45121");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15653/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514957/100/0/threaded");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/multiple-vulnerabilities-in-bugtracker");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bugtracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BugTrackerNET/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack
  and to conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"BugTracker.NET version prior to 3.4.5.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Input passed to the 'pcd' parameter in edit_bug.aspx, 'bug_id' parameter
  in edit_comment.aspx, 'default_name' parameter in edit_customfield.aspx,
  and 'id' parameter in edit_user_permissions2.aspx is not properly sanitised
  before being returned to the user.

  - Input passed via the 'qu_id' parameter to bugs.aspx, 'row_id' parameter to
  delete_query.aspx, 'us_id' and 'new_project' parameters to edit_bug.aspx,
  and 'bug_list' parameter to massedit.aspx is not properly sanitised before
  being used in a SQL query.");

  script_tag(name:"solution", value:"Upgrade to BugTracker.NET version 3.4.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"BugTracker.NET is prone to cross-site scripting and SQL injection vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(ver = get_version_from_kb(port:port, app:"btnet"))
{
  if(version_is_less(version:ver, test_version: "3.4.5")){
    report = report_fixed_ver(installed_version:ver, fixed_version:"3.4.5");
    security_message(port: port, data: report);
  }
}

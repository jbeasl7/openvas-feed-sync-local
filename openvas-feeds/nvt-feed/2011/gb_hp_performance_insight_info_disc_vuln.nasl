# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:openview_performance_insight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902417");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-1536");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("HP Performance Insight Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_performance_insight_detect.nasl");
  script_mandatory_keys("hp/openview_performance_insight/detected");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1060");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.bugtraq/46897");
  script_xref(name:"URL", value:"http://www.criticalwatch.com/support/security-advisories.aspx?AID=35689");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02790298");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to gain knowledge of sensitive
  information.");

  script_tag(name:"affected", value:"HP Performance Insight version 5.41.002 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by an unknown error which could be exploited remotely to
  access sensitive information.");

  script_tag(name:"summary", value:"HP Performance Insight is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Upgrade to HP Performance Insight 5.41.002 and apply the
  HF04 / QCCR1B88272 hotfix.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.41.002")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.41.002 with HF04 / QCCR1B88272 hotfix", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

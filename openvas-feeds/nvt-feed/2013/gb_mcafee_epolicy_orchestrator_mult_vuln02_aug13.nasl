# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803865");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-4882", "CVE-2013-4883");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-09 15:40:39 +0530 (Fri, 09 Aug 2013)");
  script_name("McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-02 (Aug 2013)");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator version 4.5.7 or higher.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Multiple flaws exist due to improper sanitation of user supplied input via:

  - 'instanceId' parameter upon submission to the /core/loadDisplayType.do
  script.

  - 'instanceId', 'orion.user.security.token', and 'ajaxMode' parameters upon
  submission to the /console/createDashboardContainer.do script.

  - 'uid' parameter upon submission to the /core/showRegisteredTypeDetails.do
  and /ComputerMgmt/sysDetPanelBoolPie.do scripts.

  - 'uid', 'orion.user.security.token', and 'ajaxMode' parameters upon submission
  to the /ComputerMgmt/sysDetPanelSummary.do and /ComputerMgmt/sysDetPanelQry.do
  scripts.");
  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator (ePO) version 4.6.6 and earlier");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
or script code in a user's browser session in the context of an affected
site and inject or manipulate SQL queries in the back-end database, allowing
for the manipulation or disclosure of arbitrary data.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61422");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26807");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB78824");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"4.6.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.6.7");
  security_message(port:port, data:report);
  exit(0);
}

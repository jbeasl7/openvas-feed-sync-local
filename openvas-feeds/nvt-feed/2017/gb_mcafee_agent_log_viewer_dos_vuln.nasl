# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810602");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-3896");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-26 01:29:00 +0000 (Wed, 26 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-16 12:13:05 +0530 (Thu, 16 Feb 2017)");
  script_name("McAfee Agent (MA) 'log viewer' Denial of Service Vulnerability");

  script_tag(name:"summary", value:"McAfee Agent is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the remote
  log viewing functionality, where an input parameter passed through the URL is
  not completely validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"McAfee Agent (MA) version 5.0.x before
  5.0.4 Hotfix 1174804 (5.0.4.449).");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent (MA) 5.0.4 hotfix
  1174804 (5.0.4.449) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  ## This issue is encountered only if both of the following two conditions are met (not enabled by default):
  ## McAfee Agent remote log viewing functionality is enabled.
  ## Remote logs access is not restricted to ePolicy Orchestrator administrators only.
  script_tag(name:"qod", value:"30");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10183");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95903");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_mcafee_agent_detect.nasl");
  script_mandatory_keys("McAfee/Agent/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(agentVer =~ "^5\.0\.")
{
  if(version_is_less(version:agentVer, test_version:"5.0.4.449"))
  {
    report = report_fixed_ver(installed_version:agentVer, fixed_version:"5.0.4 Hotfix 1174804 (5.0.4.449)");
    security_message(data:report);
    exit(0);
  }
}

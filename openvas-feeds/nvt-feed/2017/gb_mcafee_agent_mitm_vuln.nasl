# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810836");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2015-8987");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-23 17:11:00 +0000 (Thu, 23 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-04-10 16:26:54 +0530 (Mon, 10 Apr 2017)");
  script_name("McAfee Agent (MA) Man-in-the-Middle Attack Vulnerability");

  script_tag(name:"summary", value:"McAfee Agent is prone to mitm attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when McAfee Agents migrate
  from one ePO server to another.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to make a McAfee Agent talk with another, possibly rogue, ePO server via McAfee
  Agent migration to another ePO server.");

  script_tag(name:"affected", value:"McAfee Agent version prior to 4.8.0 patch 3");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent 4.8.0 patch 3.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10101");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_agent_detect.nasl");
  script_mandatory_keys("McAfee/Agent/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

## 4.8.0 patch 3 ==> 4.8.0.1938
##https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/25000/PD25667/en_US/McAfee_Agent_4_8_0_Patch3_RN.pdf
if(version_is_less(version:agentVer, test_version:"4.8.0.1938"))
{
  report = report_fixed_ver(installed_version:agentVer, fixed_version:"4.8.0 Patch 3");
  security_message(data:report);
  exit(0);
}

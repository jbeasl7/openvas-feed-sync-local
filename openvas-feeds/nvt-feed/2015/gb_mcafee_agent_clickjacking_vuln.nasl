# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805294");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2053");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-02 15:30:43 +0530 (Mon, 02 Mar 2015)");
  script_name("McAfee Agent (MA) Log Viewing Feature Unspecified Clickjacking Vulnerability");

  script_tag(name:"summary", value:"McAfee Agent is prone to clickjacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error
  in the log viewing feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to conduct a clickjacking attack.");

  script_tag(name:"affected", value:"McAfee Agent (MA) before version 4.8.0
  Patch 3 and version 5.0.0");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent (MA) 4.8.0 Patch 3
  or 5.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10094");

  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(agentVer =~ "^5\.")
{
  if(version_is_equal(version:agentVer, test_version:"5.0.0.2620"))
  {
    fix = "5.0.1";
    VULN = TRUE;
  }
} else
{
  if(version_is_less(version:agentVer, test_version:"4.8.0.1938"))
  {
    fix = "4.8.0 Patch 3";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed version: ' + agentVer + '\n' +
           'Fixed version:     ' + fix + '\n';

  security_message(data:report);
  exit(0);
}

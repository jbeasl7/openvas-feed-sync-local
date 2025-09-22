# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806638");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-7237");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-02 11:14:16 +0530 (Wed, 02 Dec 2015)");
  script_name("McAfee Agent (MA) Log Viewing Functionality Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"McAfee Agent is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the remote log viewing
  functionality where the inputs passed to the URL are not completely validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"McAfee Agent (MA) version 5.x before
  5.0.2");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent (MA) 5.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10130");

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
  ## https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26042/en_US/ma_502_rn_en-us.pdf
  if(version_is_less(version:agentVer, test_version:"5.0.2.132"))
  {
    report = 'Installed version: ' + agentVer + '\n' +
             'Fixed version:     5.0.2\n';
    security_message(data:report);
    exit(0);
  }
}

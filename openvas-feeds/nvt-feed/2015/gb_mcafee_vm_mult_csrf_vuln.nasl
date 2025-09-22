# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:vulnerability_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806611");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2015-7612");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-11-05 15:43:08 +0530 (Thu, 05 Nov 2015)");
  script_name("McAfee Vulnerability Manager Multiple CSRF Vulnerabilities");

  script_tag(name:"summary", value:"McAfee Vulnerability Manager is prone to multiple cross-site
  request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'Organizations' page in the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to conduct cross-site request forgery attacks.");

  script_tag(name:"affected", value:"McAfee Vulnerability Manager 7.5.9 and
  earlier.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix this
  issue, please see the references for more info.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033682");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10135");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_vulnerability_manager_detect.nasl");
  script_mandatory_keys("McAfee/Vulnerability/Manager");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:mVer, test_version:"7.5.9.05013"))
{
  report = 'Installed Version: ' + mVer + '\nFixed Version: 7.5.9.05013' + '\n';
  security_message(data:report);
  exit(0);
}

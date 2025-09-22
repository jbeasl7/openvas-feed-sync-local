# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:sizer_for_converged_systems_virtualization";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809438");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-4377");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:17:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-10-10 12:59:16 +0530 (Mon, 10 Oct 2016)");
  script_name("HPE Sizer ConvergedSystems Virtualization Remote Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"HPE Sizer ConvergedSystems Virtualization is prone to a remote arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  arbitrary code execution.");

  script_tag(name:"affected", value:"HPE Sizer for ConvergedSystems Virtualization
  prior to version 16.7.1.");

  script_tag(name:"solution", value:"Upgrade to HPE Sizer for ConvergedSystems
  Virtualization version 16.7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05237578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92479");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_hpe_sizer_convergedsystems_virtualization_detect.nasl");
  script_mandatory_keys("HPE/ConvergedSystems/Virtualization/Sizing/Tool/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:hpVer, test_version:"16.7.1"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"16.7.1");
  security_message(data:report);
  exit(0);
}

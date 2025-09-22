# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:tivoli_storage_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808637");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-2894");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-10-04 13:52:16 +0530 (Tue, 04 Oct 2016)");
  script_name("IBM Tivoli Storage Manager Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"IBM Tivoli Storage Manager is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the ACL associated with a
  file or directory object may be lost after an archive/retrieve on some condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  user to access files they are otherwise not allowed to access.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager version 5.5 through
  6.3 before 6.3.2.6, 6.4 before 6.4.3.3, and 7.1 before 7.1.6");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Storage Manager version
  6.3.2.6, or 6.4.3.3, or 7.1.6, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21985579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91534");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_tiv_tsm_detect_lin.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:tivVer, test_version:"5.5", test_version2:"6.3.2.5"))
{
  fix = "6.3.2.6";
  VULN = TRUE;
}

else if(version_in_range(version:tivVer, test_version:"6.4", test_version2:"6.4.3.2"))
{
  fix = "6.4.3.3";
  VULN = TRUE;
}

else if(version_in_range(version:tivVer, test_version:"7.1", test_version2:"7.1.5"))
{
  fix = "7.1.6";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

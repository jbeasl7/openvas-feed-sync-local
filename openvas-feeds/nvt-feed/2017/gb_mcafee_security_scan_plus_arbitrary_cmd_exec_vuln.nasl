# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:intel:mcafee_security_scan_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810825");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-8026");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-02 01:59:00 +0000 (Tue, 02 May 2017)");
  script_tag(name:"creation_date", value:"2017-03-22 11:47:02 +0530 (Wed, 22 Mar 2017)");
  script_name("McAfee Security Scan Plus Arbitrary Command Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"McAfee Security Scan Plus is prone to an arbitrary command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  authenticated users to gain elevated privileges via unspecified vectors.");

  script_tag(name:"affected", value:"McAfee Security Scan Plus version prior
  to 3.11.474.2");

  script_tag(name:"solution", value:"Upgrade to McAfee Security scan plus
  3.11.474.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102614");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mcafee_security_scan_plus_detect.nasl");
  script_mandatory_keys("McAfee/SecurityScanPlus/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msspVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:msspVer, test_version:"3.11.474.2"))
{
  report = report_fixed_ver(installed_version:msspVer, fixed_version:"3.11.474.2");
  security_message(data:report);
  exit(0);
}

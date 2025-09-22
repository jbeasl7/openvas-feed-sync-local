# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:intel:mcafee_security_scan_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810826");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-8991");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-28 18:28:00 +0000 (Tue, 28 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-03-22 11:57:02 +0530 (Wed, 22 Mar 2017)");
  script_name("McAfee Security Scan Plus File Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"McAfee Security Scan Plus is prone to file execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists only within installers and
  uninstallers, and may manifest only during installation or uninstallation
  operations.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to make the product momentarily vulnerable via executing preexisting
  specifically crafted malware during installation or uninstallation, but not
  during normal operation.");

  script_tag(name:"affected", value:"McAfee Security Scan Plus version prior to
  3.11.266.3.");

  script_tag(name:"solution", value:"Upgrade to McAfee Security scan plus 3.11.266.3");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102462");
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

if(version_is_less(version:msspVer, test_version:"3.11.266.3"))
{
  report = report_fixed_ver(installed_version:msspVer, fixed_version:"3.11.266.3");
  security_message(data:report);
  exit(0);
}

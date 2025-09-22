# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809333");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-8856");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-08 17:31:49 +0530 (Tue, 08 Nov 2016)");
  script_name("Foxit Reader Arbitrary Code Execution Vulnerability - Linux");

  script_tag(name:"summary", value:"Foxit Reader is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Foxit Reader's core
  files are world-writable by default.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to overwrite core files with backdoor code, which when executed by
  privileged user would result in Privilege Escalation, Code Execution, or both.");

  script_tag(name:"affected", value:"Foxit Reader version 2.1.0.0805 and
  earlier");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version
  2.2.1025 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93608");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_lin.nasl");
  script_mandatory_keys("foxit/reader/linux/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

## 2.2.1025 is the latest version available
if(version_is_less_equal(version:foxitVer, test_version:"2.1.0.0805"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"2.2.1025");
  security_message(data:report);
  exit(0);
}

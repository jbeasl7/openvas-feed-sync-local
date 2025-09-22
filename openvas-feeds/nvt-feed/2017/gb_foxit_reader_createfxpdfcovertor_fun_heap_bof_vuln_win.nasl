# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810906");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-3740");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-11 16:42:00 +0000 (Tue, 11 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-04-07 17:41:48 +0530 (Fri, 07 Apr 2017)");
  script_name("Foxit Reader 'CreateFXPDFConvertor' Function Buffer Overflow Vulnerability - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to heap based buffer overfolw vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to heap-based buffer
  overflow error in the 'CreateFXPDFConvertor' function in
  'ConvertToPdf_x86.dll'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via crafted TIFF image.");

  script_tag(name:"affected", value:"Foxit Reader version 7.3.4.311");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 8.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://0patch.blogspot.in/2016/07/0patching-foxit-readers-heap-buffer.html");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:foxitVer, test_version:"7.3.4.311"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.0");
  security_message(data:report);
  exit(0);
}

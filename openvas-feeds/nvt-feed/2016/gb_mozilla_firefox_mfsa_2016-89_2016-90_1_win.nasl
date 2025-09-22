# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox:x64";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809809");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-9072");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 14:20:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2016-11-16 12:21:41 +0530 (Wed, 16 Nov 2016)");
  script_name("Mozilla Firefox Security Advisories (MFSA2016-89, MFSA2016-90) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:
  64-bit NPAPI sandbox is not enabled on fresh profile.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  50 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 50
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-89");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94336");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver", "SMB/Windows/Arch");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!osArch = get_kb_item("SMB/Windows/Arch")){
  exit(0);
}

## if not 64bit arch, exit.
if("x64" >!< osArch){
  exit(0);
}

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"50.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"50.0");
  security_message(data:report);
  exit(0);
}

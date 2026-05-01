# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810855");
  script_version("2026-04-28T06:28:06+0000");
  script_cve_id("CVE-2017-0197");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-04-12 15:58:01 +0530 (Wed, 12 Apr 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft OneNote DLL Loading RCE Vulnerability (KB3191829)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft security updates KB3191829.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist when Office improperly validates input before
  loading dynamic link library (DLL) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to take
  control of the affected system.");

  script_tag(name:"affected", value:"Microsoft OneNote 2007 Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3191829");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97411");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/OneNote/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

path = infos["location"];
if(!path || "Could not find the install location" >< path)
  exit(0);

vers = fetch_file_version(sysPath:path, file_name:"onenotesyncpc.dll");
if(vers && vers =~ "^12\.") {
  if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.0.6765.4999")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"12.0 - 12.0.6765.4999", file_checked:path + "\onenotesyncpc.dll");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
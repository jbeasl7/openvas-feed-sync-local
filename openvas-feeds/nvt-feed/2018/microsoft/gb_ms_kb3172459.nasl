# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812902");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-0853");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-14 09:14:46 +0530 (Wed, 14 Feb 2018)");
  script_name("Microsoft Office 2013 Service Pack 1 Information Disclosure Vulnerability (KB3172459)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3172459");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Microsoft Office software which reads out of bound memory due to an
  uninitialized variable, which could disclose the contents of memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to view out of bound memory.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3172459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102868");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

offVer = get_kb_item("MS/Office/Ver");
if(!offVer || offVer !~ "^15\."){
  exit(0);
}

msPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
if(msPath)
{
  offPath = msPath + "\Microsoft Shared\Office15";
  msdllVer = fetch_file_version(sysPath:offPath, file_name:"acecore.dll");

  if(msdllVer && msdllVer =~ "^15\.")
  {
    if(version_is_less(version:msdllVer, test_version:"15.0.5007.1000"))
    {
      report = report_fixed_ver(file_checked:offPath + "\acecore.dll",
                                file_version:msdllVer, vulnerable_range:"15.0 - 15.0.5007.0999");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);

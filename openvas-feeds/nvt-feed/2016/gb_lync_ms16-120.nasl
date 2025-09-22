# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809444");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3209", "CVE-2016-3262", "CVE-2016-3263", "CVE-2016-3396",
                "CVE-2016-7182");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-12 12:47:25 +0530 (Wed, 12 Oct 2016)");
  script_name("Microsoft Lync Multiple Vulnerabilities (3192884)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-120.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Windows Graphics Device Interface (GDI) improperly handles objects
    in memory.

  - The windows font library which improperly handles specially crafted
    embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system and gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Lync 2010

  - Microsoft Lync 2013");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3192884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93385");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93380");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93395");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-120");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Installed");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(get_kb_item("MS/Lync/Ver"))
{
  lyncPath = get_kb_item("MS/Lync/path");

  ## For MS Lync Basic
  if(!lyncPath){
    lyncPath = get_kb_item("MS/Lync/Basic/path");
  }

  if(lyncPath)
  {
    lyncPath1 = lyncPath + "OFFICE14";
    commVer = fetch_file_version(sysPath:lyncPath1, file_name:"Rtmpltfm.dll");
    if(commVer)
    {
      if(commVer =~ "^4" && version_in_range(version:commVer, test_version:"4.0", test_version2:"4.0.7577.4520"))
      {
        report = 'File checked:     ' + lyncPath1 + "\Rtmpltfm.dll" + '\n' +
                 'File version:     ' + commVer  + '\n' +
                 'Vulnerable range: ' + "4.0 - 4.0.7577.4520" + '\n' ;
        security_message(data:report);
      }
    }

    lyncPath2 = lyncPath + "OFFICE15";
    fileVer = fetch_file_version(sysPath:lyncPath2, file_name:"lynchtmlconv.exe");
    if(fileVer)
    {
      if(version_in_range(version:fileVer, test_version:"15.0", test_version2:"15.0.4867.999"))
      {
        report = 'File checked:     ' + lyncPath2 + "\lynchtmlconv.exe" + '\n' +
                 'File version:     ' + fileVer  + '\n' +
                 'Vulnerable range: ' + "15.0 - 15.0.4867.0999" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}


# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809313");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0138", "CVE-2016-3378", "CVE-2016-3379");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-09-14 10:21:52 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Exchange Server Multiple Vulnerabilities (3185883)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-108.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - The way that Microsoft Exchange Server parses email messages.

  - An open redirect vulnerability exists in Microsoft Exchange that
    could lead to Spoofing.

  - The way that Microsoft Outlook handles meeting invitation requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  an attacker to discover confidential user information that is contained in
  Microsoft Outlook applications, also attacker could trick the user and potentially
  acquire sensitive information, such as the user's credentials.");

  script_tag(name:"affected", value:"- Microsoft Exchange Server 2013 Service Pack 1

  - Microsoft Exchange Server 2013 Cumulative Update 12

  - Microsoft Exchange Server 2013 Cumulative Update 13

  - Microsoft Exchange Server 2016 Cumulative Update 1

  - Microsoft Exchange Server 2016 Cumulative Update 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3184736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92836");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-108");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Exchange/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exchangePath = get_app_location(cpe:CPE, skip_port:TRUE);
if(!exchangePath || "Could not find the install location" >< exchangePath){
  exit(0);
}

cum_update = get_kb_item("MS/Exchange/Cumulative/Update/no");

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(exeVer)
{
  ## Exchange Server 2013
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.49"))
  {
    Vulnerable_range = "15.0 - 15.0.847.50";
    VULN = TRUE ;
  }

  ## Exchange Server 2013 CU 13
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 13" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1210.6"))
    {
      Vulnerable_range = "Less than 15.0.1210.6";
      VULN = TRUE ;
    }
  }

  ## Exchange Server 2013 CU 12
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 12" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1178.9"))
    {
      Vulnerable_range = "Less than 15.0.1178.9";
      VULN = TRUE ;
    }
  }

  ##Exchange Server 2016 CU 1
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 1" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.396.37"))
    {
      Vulnerable_range = "Less than 15.1.396.37";
      VULN = TRUE ;
    }
  }

  ##Exchange Server 2016 CU 2
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 2" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.466.37"))
    {
      Vulnerable_range = "Less than 15.1.466.37";
      VULN = TRUE ;
    }
  }

}

if(VULN)
{
  report = 'File checked:     ' + exchangePath + "\Bin\ExSetup.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

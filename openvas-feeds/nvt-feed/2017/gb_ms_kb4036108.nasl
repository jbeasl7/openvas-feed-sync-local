# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811761");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-11761", "CVE-2017-8758");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-09 13:15:00 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-09-14 10:51:52 +0530 (Thu, 14 Sep 2017)");
  script_name("Microsoft Exchange Server Multiple Vulnerabilities (KB4036108)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4036108");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an error in the
  way that Microsoft Exchange Server parses Calendar-related messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Exchange Server 2016 CU5

  - Microsoft Exchange Server 2016 CU6

  - Microsoft Exchange Server 2013 CU16

  - Microsoft Exchange Server 2013 CU17

  - Microsoft Exchange Server 2013 SP1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4036108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100731");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100723");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_mandatory_keys("MS/Exchange/Server/Ver");
  script_require_ports(139, 445);
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

  ## Security Update For Exchange Server 2013 SP1
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.56")){
    Vulnerable_range = "15.0 - 15.0.847.56";
  }

  ## Security Update For Exchange Server 2013 CU17
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 17" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1320.6")){
      Vulnerable_range = "15.0 - 15.0.1320.5";
    }
  }

  ## Security Update For Exchange Server 2013 CU16
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 16" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1293.6")){
      Vulnerable_range = "15.0 - 15.0.1293.5";
    }
  }

  ## Security Update For Exchange Server 2016 CU6
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 6" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.1034.32")){
      Vulnerable_range = "15.1 - 15.1.1034.31";
    }
  }

  ## Security Update For Exchange Server 2016 CU5
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 5" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.845.39")){
      Vulnerable_range = "15.1 - 15.1.845.38";
    }
  }
}

if(Vulnerable_range)
{
  report = 'File checked:     ' + exchangePath + "\Bin\ExSetup.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);

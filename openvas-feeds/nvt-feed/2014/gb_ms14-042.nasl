# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804474");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-2814");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-09 15:14:23 +0530 (Wed, 09 Jul 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Windows Service Bus Denial of Service Vulnerability (2972621)");

  script_tag(name:"summary", value:"This host is missing a moderate security update according to
  Microsoft Bulletin MS14-042.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error when handling Advanced Message
  Queuing Protocol (AMQP) messages and can be exploited to cause Microsoft
  Service Bus to stop responding to incoming messages by sending specially
  crafted AMQP messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a Denial
  of Service.");

  script_tag(name:"affected", value:"- Microsoft Service Bus 1.1 on Microsoft Windows Server 2012/R2

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2972621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68393");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-042");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp( win2008r2:2, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

buskey = "SOFTWARE\Microsoft\Service Bus\1.1";

if(!registry_key_exists(key:buskey)){
  exit(0);
}

sysPath = registry_get_sz(key:buskey, item:"INSTALLDIR");
if("Service Bus" >!< sysPath){
  exit(0);
}

Win32sysVer = fetch_file_version(sysPath:sysPath, file_name:"Microsoft.ServiceBus.dll");
if(!Win32sysVer){
  exit(0);
}

if(version_is_less(version:Win32sysVer, test_version:"2.1.40512.2"))
{
  report = report_fixed_ver(installed_version:Win32sysVer, fixed_version:"2.1.40512.2", install_path:sysPath);
  security_message(port:0, data:report);
  exit(0);
}

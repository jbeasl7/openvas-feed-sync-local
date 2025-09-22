# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803000");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4068");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-02 18:48:06 +0530 (Thu, 02 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Citrix Provisioning Services SoapServer Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48971/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53330");
  script_xref(name:"URL", value:"http://support.citrix.com/article/ctx133039");
  script_xref(name:"URL", value:"http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=979");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_citrix_provisioning_services_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Citrix/Provisioning/Services/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the target system.");
  script_tag(name:"affected", value:"Citrix Provisioning Services version 5.6 and prior, 6.0 and 6.1");
  script_tag(name:"insight", value:"The SoapServer service improperly calculates a buffer index pointer value
  for a date and time string, which references a location outside the fixed
  sized heap buffer resulting in a heap buffer overflow.");
  script_tag(name:"solution", value:"Apply the hotfix for Citrix Provisioning Services from the referenced advisory.");
  script_tag(name:"summary", value:"Citrix Provisioning Services is prone to a buffer overflow vulnerability.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

prodVer = get_kb_item("Citrix/Provisioning/Services/Ver");
if(!prodVer){
  exit(0);
}

prodLoc = get_kb_item("Citrix/Provisioning/Services/path");
if(!prodLoc || "Provisioning Services" >!< prodLoc){
  exit(0);
}

fileVer = fetch_file_version(sysPath: prodLoc, file_name:"StreamProcess.exe");
if(!fileVer){
  exit(0);
}

## for 6.0.0 through 6.0.0.1083 , 6.1.0 through 6.1.0.1082
if(version_is_less(version:fileVer, test_version:"5.6.3.1349")||
   version_in_range(version:fileVer, test_version:"6.0.0", test_version2:"6.0.0.1083")||
   version_in_range(version:fileVer, test_version:"6.1.0", test_version2:"6.1.0.1082")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

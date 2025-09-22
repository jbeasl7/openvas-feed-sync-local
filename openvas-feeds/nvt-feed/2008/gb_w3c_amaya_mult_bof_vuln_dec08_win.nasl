# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800311");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-12-09 13:27:23 +0100 (Tue, 09 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5282");
  script_name("W3C Amaya Multiple Buffer Overflow Vulnerabilities (Dec 2008) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32442");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisories/amaya-id.txt");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisories/amaya-url.txt");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3255");
  script_xref(name:"URL", value:"http://www.w3.org/Amaya/User/BinDist.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code or
  crash an affected browser.");

  script_tag(name:"affected", value:"W3C Amaya Web Browser Version 10.0.1 and prior on Windows");

  script_tag(name:"insight", value:"The flaws are due to boundary error when processing,

  - HTML <div> tag with a long id field.

  - link with a long HREF attribute.");

  script_tag(name:"solution", value:"Update to a later version.");

  script_tag(name:"summary", value:"W3C Amaya Web Browser is prone to Multiple Stack based Buffer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

keys = registry_enum_keys(key:key);

foreach item (keys)
{
  if("Amaya" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    w3cVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!w3cVer){
      exit(0);
    }

    if(version_is_less_equal(version:w3cVer, test_version:"10.0.1")){
      report = report_fixed_ver(installed_version:w3cVer, vulnerable_range:"Less than or equal to 10.0.1");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

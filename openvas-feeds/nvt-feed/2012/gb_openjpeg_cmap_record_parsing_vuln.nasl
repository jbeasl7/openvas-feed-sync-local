# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903019");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-1499");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-25 11:28:15 +0530 (Wed, 25 Apr 2012)");
  script_name("OpenJPEG CMAP Record Parsing Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48498/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52654");
  script_xref(name:"URL", value:"http://openjpeg.googlecode.com/svn/branches/openjpeg-1.5/NEWS");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/VulnerabilityResearchAdvisories/2012/msvr12-004#section1");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to an error when parsing a CMAP record and can be
  exploited to cause an out of bounds write via specially crafted JPEG files.");
  script_tag(name:"solution", value:"Upgrade to the OpenJPEG version 1.5 or later.");
  script_tag(name:"summary", value:"OpenJPEG is prone to record parsing vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"OpenJPEG version prior to 1.5");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\openjpeg";
if(!registry_key_exists(key:key)){
  exit(0);
}

openName = registry_get_sz(key:key, item:"DisplayName");
if("OpenJPEG" >< openName)
{
  openVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(!openVer){
    exit(0);
  }

  if(version_is_less(version:openVer, test_version:"1.5")){
    report = report_fixed_ver(installed_version:openVer, fixed_version:"1.5");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

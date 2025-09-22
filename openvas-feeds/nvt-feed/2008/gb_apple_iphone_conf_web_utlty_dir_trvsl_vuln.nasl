# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800080");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2008-5315");
  script_name("Apple iPhone Configuration Web Utility Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32412");
  script_xref(name:"URL", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2008-November/065822.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to download arbitrary files
  from the affected system via directory traversal attacks.");

  script_tag(name:"affected", value:"iPhone Configuration Web Utility 1.0.x for Windows");

  script_tag(name:"insight", value:"The issue is due to an input validation error when processing HTTP
  GET requests.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to iPhone Configuration Utility 1.1.");

  script_tag(name:"summary", value:"Apple iPhone Configuration Web Utility is prone to a directory traversal vulnerability.");

  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Apple Inc.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  iPhoneName = registry_get_sz(item:"DisplayName", key:key +item);
  if(iPhoneName =~ "iPhone Configuration.*Utility")
  {
    iPhoneVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(!iPhoneVer){
      exit(0);
    }

    if(version_is_less(version:iPhoneVer, test_version:"1.1.0.43")){
      report = report_fixed_ver(installed_version:iPhoneVer, fixed_version:"1.1.0.43");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
}

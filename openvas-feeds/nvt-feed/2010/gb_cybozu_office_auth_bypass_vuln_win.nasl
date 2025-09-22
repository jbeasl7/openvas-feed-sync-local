# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902060");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2029");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Cybozu Office Authentication Bypass Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to insufficient checks being performed when accessing
  the 'login' interface.");
  script_tag(name:"solution", value:"Upgrade to Cybozu Office 8 (8.1.0.1).");
  script_tag(name:"summary", value:"Cybozu Office is prone to an authentication bypass vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass authentication
  and obtain or modify sensitive information by using the unique ID of the
  'user&qts' cell phone.");
  script_tag(name:"affected", value:"Cybozu Office before 8 (8.1.0.1).");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39508");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57976");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN87730223/index.html");
  script_xref(name:"URL", value:"http://www.ipa.go.jp/security/english/vuln/201004_cybozu_en.html");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\Cybozu, Inc."))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key))
  exit(0);

foreach item (registry_enum_keys(key:key))
{
  cbofName = registry_get_sz(key:key + item, item:"Publisher");

  if("Cybozu, Inc." >< cbofName)
  {
    cbofVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if (cbofVer != NULL)
    {
       if(version_is_less(version:cbofVer, test_version:"8.1.0.1")){
         report = report_fixed_ver(installed_version:cbofVer, fixed_version:"8.1.0.1");
         security_message(port: 0, data: report);
      }
    }
  }
}

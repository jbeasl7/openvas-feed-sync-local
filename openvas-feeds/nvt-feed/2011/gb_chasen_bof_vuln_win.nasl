# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802343");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-4000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-09 16:19:55 +0530 (Wed, 09 Nov 2011)");
  script_name("ChaSen Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN16901583/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000099.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a buffer overflow
  or execute arbitrary code.");
  script_tag(name:"affected", value:"ChaSen Version 2.4.x");
  script_tag(name:"insight", value:"The flaw is due to an error when reading user-supplied input string,
  which allows attackers to execute arbitrary code via a crafted string.");
  script_tag(name:"solution", value:"Use ChaSen Version 2.3.3.");
  script_tag(name:"summary", value:"ChaSen Software is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\chasen";
if(!registry_key_exists(key:key)){
  exit(0);
}

chaName = registry_get_sz(key:key, item:"DisplayName");
if("ChaSen" >< chaName)
{
  chaVer = eregmatch(pattern:"ChaSen ([0-9.]+)", string:chaName);
  if(chaVer[1] != NULL)
  {
    if(version_in_range(version:chaVer[1], test_version:"2.4.0", test_version2:"2.4.4")){
      report = report_fixed_ver(installed_version:chaVer[1], vulnerable_range:"2.4.0 - 2.4.4");
      security_message(port: 0, data: report);
    }
  }
}

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802154");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2594");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("KMPlayer '.kpl' File 'Title' Field Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49342");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69451");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation allows attackers to overflow a buffer
  and execute arbitrary code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"KMPlayer versions 3.0.0.1441 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when parsing the
  'Title' entry within play list files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"KMPlayer is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\KMPlayer"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\The KMPlayer";
if(!registry_key_exists(key:key))
  exit(0);

kmName = registry_get_sz(key:key, item:"DisplayName");
if("KMPlayer" >< kmName) {
  kmPath = registry_get_sz(key:key, item:"UninstallString");
  if(kmPath) {
    kmPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:kmPath);
    kmPath = ereg_replace(pattern:'uninstall.exe', replace:"", string:kmPath);

    kmVer = fetch_file_version(sysPath:kmPath, file_name:"KMPlayer.exe");
    if(!kmVer)
      exit(0);

    if(version_is_less_equal(version:kmVer, test_version:"3.0.0.1441")) {
      report = report_fixed_ver(installed_version:kmVer, fixed_version:"None", file_checked:kmPath);
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);

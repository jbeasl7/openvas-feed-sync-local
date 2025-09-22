# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902071");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1685");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CursorArts ZipWrangler 'ZIP Processing' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39575");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-031-zip-wrangler-1-20-buffer-overflow/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to boundary error when processing certain
ZIP files, which leads to stack-based buffer overflow by tricking a user into
opening a specially crafted ZIP file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"CursorArts ZipWrangler is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code with a specially crafted ZIP file.");
  script_tag(name:"affected", value:"CursorArts ZipWrangler version 1.20.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
         "\ZipWrangler version 1.20_is1";

if(!registry_key_exists(key:key)){
  exit(0);
}

zipName = registry_get_sz(key:key, item:"DisplayName");
if("ZipWrangler" >< zipName)
{
  zipVer = eregmatch(pattern:" version ([0-9.]+)", string:zipName);
  if(zipVer[1] != NULL)
  {
    if(version_is_equal(version:zipVer[1], test_version:"1.20")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

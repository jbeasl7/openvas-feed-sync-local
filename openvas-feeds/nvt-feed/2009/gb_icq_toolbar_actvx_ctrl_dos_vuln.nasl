# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800694");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7135", "CVE-2008-7136");
  script_name("ICQ Toolbar 'toolbaru.dll' ActiveX Control Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28118");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41014");
  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/5WP0115NPU.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_icq_toolbar_detect.nasl");
  script_mandatory_keys("ICQ/Toolbar/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to crash the
toolbar.");
  script_tag(name:"affected", value:"ICQ Toolbar version 2.3 beta and prior.");
  script_tag(name:"insight", value:"This flaw is due to an error in 'toolbaru.dll' when processing
a long argument to the (1) RequestURL, (2) GetPropertyById, (3) SetPropertyById
or (4) IsChecked method.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"ICQ Toolbar is prone to a remote denial of service (DoS) vulnerability");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

icqVer = get_kb_item("ICQ/Toolbar/Ver");
if(!icqVer)
{
  exit(0);
}

path=registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                                              item:"ProgramFilesDir");
path = path + "\ICQToolbar\toolbaru.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

dllSize = get_file_size(share:share, file:file);
if(dllSize)
{
  if(version_is_less_equal(version:icqVer, test_version:"2.3.beta"))
  {
    if(is_killbit_set(clsid:"{855F3B16-6D32-4FE6-8A56-BBB695989046") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

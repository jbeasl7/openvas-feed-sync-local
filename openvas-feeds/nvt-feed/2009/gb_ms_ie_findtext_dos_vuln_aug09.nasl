# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800861");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2655");
  script_name("Microsoft Internet Explorer 'findText()' Unicode Parsing DoS Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9253");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35799");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version", "SMB/WinXP/ServicePack");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause
  the application to crash.");

  script_tag(name:"affected", value:"Microsoft, Internet Explorer version 7.x/8.x.");

  script_tag(name:"insight", value:"The flaw is due to error in mshtml.dll file and it can causes
  while calling the JavaScript findText method with a crafted Unicode string in
  the first argument, and only one additional argument, as demonstrated by a
  second argument of -1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

SP = get_kb_item("SMB/WinXP/ServicePack");
if("Service Pack 3" >< SP)
{
  ieVer = get_kb_item("MS/IE/Version");
  if(ieVer =~ "^[7|8]\..*")
  {
    dllPath = registry_get_sz(item:"Install Path", key:"SOFTWARE\Microsoft\COM3\Setup");
    dllPath += "\mshtml.dll";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    mshtmlVer = GetVer(file:file, share:share);
    if(isnull(mshtmlVer))
      exit(0);

    if(version_in_range(version:mshtmlVer, test_version:"7.0", test_version2:"7.0.6000.16890") ||
       version_in_range(version:mshtmlVer, test_version:"8.0", test_version2:"8.0.6001.18812")) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

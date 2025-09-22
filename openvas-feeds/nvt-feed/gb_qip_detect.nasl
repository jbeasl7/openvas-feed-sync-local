# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800540");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("QIP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the QIP version.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "QIP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  qipName = registry_get_sz(key:key + item, item:"DisplayName");
  if(qipName =~ "QIP ([0-9]+)")
  {
    qipPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(qipPath == NULL){
      exit(0);
    }
    qipPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:qipPath);
    qipPath = qipPath - "unqip.exe" - "unins000.exe" + "qip.exe";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:qipPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:qipPath);
    qipVer = GetVer(file:file, share:share);

    if(qipVer)
    {
      set_kb_item(name:"QIP/Version", value:qipVer);
      log_message(data:"QIP version " + qipVer +
                         " running at location " + qipPath +
                         " was detected on the host");

      cpe = build_cpe(value:qipVer, exp:"^(8\.0\..*)", base:"cpe:/a:qip:qip:2005");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}

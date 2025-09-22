# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800969");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pegasus Mail Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script retrieves the installed version of Pegasus Mail.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Pegasus Mail Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pegasus Mail";
pmailName = registry_get_sz(key:key, item:"DisplayName");
if("Pegasus Mail" >< pmailName)
{
  pmailPath = registry_get_sz(key:key, item:"UninstallString");
  if(pmailPath)
  {
    pmailPath =  eregmatch(pattern:"^(.+(exe|EXE))(.*)?$", string:pmailPath);
    if(pmailPath[1] != NULL)
    {
      pmailPath =  pmailPath[1] - "DESETUP.EXE" - "DeSetup.exe" + "winpm-32.exe";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:pmailPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:pmailPath);

      pmailVer = GetVer(file:file, share:share);
      if(!isnull(pmailVer))
      {
        set_kb_item(name:"Pegasus/Mail/Ver", value:pmailVer);
        log_message(data:"Pegasus Mail version " + pmailVer +
                           " running at location " + pmailPath +
                           " was detected on the host");

        cpe = build_cpe(value:pmailVer, exp:"^([0-9.]+)", base:"cpe:/a:pmail:pegasus_mail:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      }
    }
  }
}

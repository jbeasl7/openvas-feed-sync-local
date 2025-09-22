# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800512");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Blazevideo HDTV Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the version of Blazevideo HDTV Player.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Blazevideo HDTV Player Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
   exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key+item, item:"DisplayName");
  if("BlazeDTV" >< appName)
  {
    bvVer = eregmatch(pattern:"BlazeDTV ([0-9.]+)", string:appName);
    if(bvVer[1] != NULL)
    {
      set_kb_item(name:"Blazevideo/HDTV/Ver", value:bvVer[1]);
      log_message(data:"Blaze Video HDTV version " + bvVer[1] +
                         " was detected on the host");

      cpe = build_cpe(value:bvVer[1], exp:"^([0-9.]+)", base:"cpe:/a:blazevideo:hdtv_player:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}

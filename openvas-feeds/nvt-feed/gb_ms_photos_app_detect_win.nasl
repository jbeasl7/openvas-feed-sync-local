# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834526");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2024-09-24 11:30:54 +0530 (Tue, 24 Sep 2024)");
  script_name("Microsoft Photos App (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of the Microsoft Photos App.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("cpe.inc");

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

key = "SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\";

if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key)) {

  if("Microsoft.Windows.Photos" >< item) {

    appPath = registry_get_sz(key:key + item, item:"Path");

    if("Microsoft.Windows.Photos" >< appPath) {

      photosVer = eregmatch(pattern:"Microsoft\.Windows\.Photos_([0-9.]+)_x", string:appPath);
      if(photosVer) {

        set_kb_item(name:"PhotosApp/Win/Ver", value:photosVer[1]);
        set_kb_item(name:"PhotosApp/Win/detected", value:TRUE);

        register_and_report_cpe(app:"Microsoft Photos App", ver:photosVer[1], concluded:photosVer[0],
                                base:"cpe:/a:microsoft:photos:", expr:"^([0-9.]+)",
                                insloc:appPath, regService:"smb-login", regPort:0);
        exit(0);
      }
    }
  }
}

exit(0);

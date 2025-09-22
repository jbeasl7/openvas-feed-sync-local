# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96195");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-08 13:13:43 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for Windows 10 Cortana Search");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Check for Windows 10 Cortana Search");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

# Exit if we don't have Windows 10 installed
CurrentMajorVersionNumber = registry_get_dword( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentMajorVersionNumber" );
if( ! CurrentMajorVersionNumber || CurrentMajorVersionNumber < 10 ) exit( 0 );

cortanaEnabled = FALSE;

# Key for Windows 10 Home and Pro Anniversary Update 1607 Build 14393.479 and up or Windows 10 1703 Creators Update.
key1 = "SOFTWARE\Microsoft\PolicyManager\current\device\Experience";

# Key for Windows 10 Home und Pro Anniversary Update 1607 Build 14328 and up
key2 = "SOFTWARE\Policies\Microsoft\Windows\Windows Search";

# Key for Windows 10 64-bit
key3 = "SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Search";

# None of the keys exist -> Cortana Search enabled
if( ! registry_key_exists( key:key1, type:"HKLM" ) &&
    ! registry_key_exists( key:key2, type:"HKLM" ) &&
    ! registry_key_exists( key:key3, type:"HKLM" ) ) {
  cortanaEnabled = TRUE;
} else {

  reskey1 = registry_get_dword( item:"AllowCortana", key:key1, type:"HKLM" );
  reskey2 = registry_get_dword( item:"AllowCortana", key:key2, type:"HKLM" );
  reskey3 = registry_get_dword( item:"AllowCortana", key:key3, type:"HKLM" );

  if( ( isnull( reskey1 ) || reskey1 == "1" ) &&
      ( isnull( reskey2 ) || reskey2 == "1" ) &&
      ( isnull( reskey3 ) || reskey3 == "1" ) ) {
    cortanaEnabled = TRUE;
  }
}

if( cortanaEnabled ) {
  log_message( port:0, data:"Cortana Search is enabled." );
  exit( 0 );
}

exit( 99 );

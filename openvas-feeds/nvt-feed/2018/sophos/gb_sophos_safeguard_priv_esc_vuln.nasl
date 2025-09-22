# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107327");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-07-04 11:36:43 +0200 (Wed, 04 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2018-6851", "CVE-2018-6852", "CVE-2018-6853", "CVE-2018-6854", "CVE-2018-6855", "CVE-2018-6856", "CVE-2018-6857");
  script_name("Sophos SafeGuard Privilege Escalation Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_sophos_safeguard_detect_win.nasl");
  script_mandatory_keys("Sophos/SafeGuard/Win/Installed");

  script_tag(name:"summary", value:"Sophos SafeGuard Client Products are prone to privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities are present within all configurations of SafeGuard Enterprise
  (SGN), SafeGuard Easy (SGE) and SafeGuard LAN Crypt (SGLC) clients running on Windows. Exploitation of those
  vulnerabilities requires running malicious code on the target machine and can result in privilege escalation.
  This vulnerability is not remotely exploitable (i.e. over the network).");

  script_tag(name:"affected", value:"SafeGuard Enterprise Client 8.00.4 and earlier, SafeGuard Easy Client 7.00.2.35 and earlier,
  SafeGuard LAN Crypt Client 3.95.1.13 and earlier.");

  script_tag(name:"solution", value:"Upgrade to SafeGuard Enterprise Client 8.00.5, SafeGuard Easy Client 7.00.3 or SafeGuard LAN Crypt Client 3.95.2.");

  script_xref(name:"URL", value:"https://labs.nettitude.com/blog/cve-2018-6851-to-cve-2018-6857-sophos-privilege-escalation-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:sophos:safeguard_lan_crypt_encryption_client", "cpe:/a:sophos:safeguard_enterprise_device_encryption_client", "cpe:/a:sophos:safeguard_easy_device_encryption_client" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if( "cpe:/a:sophos:safeguard_lan_crypt_encryption_client" >< cpe ) {
  if( version_is_less( version:vers, test_version:"3.95.2" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.95.2", install_path:path );
    security_message( data:report, port:0 );
    exit( 0 );
  }
}

else if( "cpe:/a:sophos:safeguard_enterprise_device_encryption_client" >< cpe ) {
  if( version_is_less( version:vers, test_version:"8.00.5" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"8.00.5", install_path:path );
    security_message( data:report, port:0 );
    exit( 0 );
  }
}

else if( "cpe:/a:sophos:safeguard_easy_device_encryption_client" >< cpe ) {
  if( version_is_less( version:vers, test_version:"7.00.3" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"7.00.3", install_path:path );
    security_message( data:report, port:0 );
    exit( 0 );
  }
}

exit ( 99 );

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.108315");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-12-20 12:31:33 +0100 (Wed, 20 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 14:51:00 +0000 (Thu, 21 Dec 2017)");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2017-17683", "CVE-2017-17684");

  script_name("Panda Global Protection <= 17.00.01 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GlobalProtection/Ver");

  script_tag(name:"summary", value:"Panda Global Protection through 17.00.01 is vulnerable to
  multiple vulnerabilities that can cause a system crash.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A system crash can be caused through both a 0xb3702c04 or 0xb3702c44 DeviceIoControl request.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the machine, effectively denying access to it.");

  script_tag(name:"affected", value:"Panda Global Protection through version 17.00.01.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/k0keoyo/Driver-Loaded-PoC/tree/master/Panda-Antivirus/Panda_Security_Antivirus_0xb3702c04_");
  script_xref(name:"URL", value:"https://github.com/k0keoyo/Driver-Loaded-PoC/tree/master/Panda-Antivirus/Panda_Security_Antivirus_0xb3702c44");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/a:pandasecurity:panda_global_protection_2010",
                      "cpe:/a:pandasecurity:panda_global_protection_2014" );

if( ! infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version: vers, test_version: "17.00.01" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

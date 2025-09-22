# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105823");
  script_cve_id("CVE-2016-5804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Moxa MGate Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91777");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-196-02");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass the authentication
  mechanism and perform unauthorized actions. This may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisoryfor more information.");

  script_tag(name:"summary", value:"Moxa Multiple Products are prone to an authentication-bypass vulnerability.");

  script_tag(name:"affected", value:"The following products are affected:

  MGate MB3180, versions prior to v1.8,

  MGate MB3280, versions prior to v2.7,

  MGate MB3480, versions prior to v2.6,

  MGate MB3170, versions prior to v2.5,

  MGate MB3270, versions prior to v2.7");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 15:08:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-07-25 14:23:53 +0200 (Mon, 25 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_moxa_mgate_consolidation.nasl");
  script_mandatory_keys("moxa/mgate/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:moxa:mb3280_firmware",
                     "cpe:/o:moxa:mb3270_firmware",
                     "cpe:/o:moxa:mb3180_firmware",
                     "cpe:/o:moxa:mb3170_firmware",
                     "cpe:/o:moxa:mb3480_firmware");

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];

if( ! version = get_app_version( cpe:cpe, nofork:TRUE ) )
  exit( 0 );

if( cpe == "cpe:/o:moxa:mb3280_firmware" || cpe == "cpe:/o:moxa:mb3270_firmware" ) fix = '2.7';
if( cpe == "cpe:/o:moxa:mb3180_firmware" ) fix = '1.8';
if( cpe == "cpe:/o:moxa:mb3170_firmware" ) fix = '2.5';
if( cpe == "cpe:/o:moxa:mb3480_firmware" ) fix = '2.6';

if( ! fix )
  exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

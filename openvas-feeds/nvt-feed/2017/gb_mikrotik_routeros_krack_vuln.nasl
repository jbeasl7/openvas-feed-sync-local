# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108254");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-10-18 12:31:00 +0200 (Wed, 18 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080",
                "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13084", "CVE-2017-13086",
                "CVE-2017-13087", "CVE-2017-13088");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS WPA2 Key Reinstallation Vulnerabilities - KRACK");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"WPA2 as used in MikroTik RouterOS is prone to multiple security
  weaknesses aka Key Reinstallation Attacks (KRACK).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting these issues may allow an unauthorized user to
  intercept and manipulate data or disclose sensitive information. This may aid in further
  attacks.");

  script_tag(name:"affected", value:"Affected modes:

  For AP devices: WDS WiFi/nstreme

  For CPE devices (MikroTik Station mode): WiFi, nstreme

  Affected versions prior to v6.39.3 and v6.40.x prior to v6.40.4.");

  script_tag(name:"solution", value:"Upgrade to one of the following RouterOS versions:

  - v6.39.3 or later

  - v6.40.4 or later

  - v6.41rc or later");

  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?f=21&t=126695");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101274");
  script_xref(name:"URL", value:"https://www.krackattacks.com/");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"6.39.3" ) )
  fix = "6.39.3";

if( version_in_range( version:version, test_version:"6.40", test_version2:"6.40.3" ) )
  fix = "6.40.4";

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

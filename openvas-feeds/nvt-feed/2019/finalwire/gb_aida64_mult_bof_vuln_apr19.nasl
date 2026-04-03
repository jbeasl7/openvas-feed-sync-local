# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:finalwire:aida64";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107635");
  script_version("2026-04-02T06:06:11+0000");
  script_tag(name:"last_modification", value:"2026-04-02 06:06:11 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"creation_date", value:"2019-04-05 15:15:05 +0200 (Fri, 05 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-26 16:40:24 +0000 (Thu, 26 Mar 2026)");

  script_cve_id("CVE-2019-25629", "CVE-2019-25631", "CVE-2019-25633");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("AIDA64 <= 6.25.5400 Multiple SEH BOF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_finalwire_aida64_detect_win.nasl");
  script_mandatory_keys("finalwire/aida64/detected");

  script_tag(name:"summary", value:"AIDA64 is prone to multiple local structured exception handling
  (SEH) buffer overflow (BOF) vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-25629: Local SEH BOF triggered via malicious CSV log file path in Hardware Monitoring
  preferences.

  - CVE-2019-25631: Local SEH BOF triggered via EggHunter payload injection in the SMTP display
  name field.

  - CVE-2019-25633: Local SEH BOF triggered via EggHunter payload injection in the email preferences
  and report wizard.");

  script_tag(name:"impact", value:"A local attacker could overflow a buffer and execute arbitrary
  code on the system.");

  script_tag(name:"affected", value:"AIDA64 Editions through version 6.25.5400.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46636");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46639");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46660");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"6.25.5400" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170322");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2023-02-24 21:18:49 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 20:19:00 +0000 (Wed, 08 Nov 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2015-1187");

  script_name("D-Link Multiple DIR Devices RCE Vulnerability (Sep 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"Multiple D-Link DIR devices are prone to a remote command
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The ping tool in multiple D-Link and TRENDnet devices allow
  remote attackers to execute arbitrary code via the ping_addr parameter to ping.ccp.");

  script_tag(name:"affected", value:"D-Link DIR-626L, DIR-636L, DIR-808L, DIR-810L, DIR-820L,
  DIR-826L, DIR-830L and DIR-836L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: CISA states that the impacted devices are end-of-life and should be disconnected if still
  in use.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/131465/D-Link-TRENDnet-NCC-Service-Command-Injection.html");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/130607/D-Link-DIR636L-Remote-Command-Injection.html");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Mar/15");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dir-626l_firmware",
                      "cpe:/o:dlink:dir-636l_firmware",
                      "cpe:/o:dlink:dir-808l_firmware",
                      "cpe:/o:dlink:dir-810l_firmware",
                      "cpe:/o:dlink:dir-820l_firmware",
                      "cpe:/o:dlink:dir-826l_firmware",
                      "cpe:/o:dlink:dir-830l_firmware",
                      "cpe:/o:dlink:dir-836l_firmware" );

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

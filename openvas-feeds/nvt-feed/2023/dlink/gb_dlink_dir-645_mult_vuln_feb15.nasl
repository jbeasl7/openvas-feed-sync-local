# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-645_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170315");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2023-02-22 19:26:41 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 16:05:08 +0000 (Wed, 24 Jul 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2015-2051", "CVE-2015-2052");

  script_name("D-Link DIR-645 Rev. A Devices Multiple Vulnerabilities (Feb 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-645 Rev. A devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-2051: Remote command execution via a GetDeviceSettings action to the HNAP interface.

  - CVE-2020-9377: Arbitrary code execution via a long string in a GetDeviceSettings action to the
  HNAP interface.");

  script_tag(name:"affected", value:"D-Link DIR-645 Rev A devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: CISA states that the impacted product is end-of-life and should be disconnected if still
  in use.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37171");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10282");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/pages/product.aspx?id=5ec9c4690cb84e258a81704e585167bb");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( ! hw_version = get_kb_item( "d-link/dir/hw_version" ) )
  exit( 0 );

if ( hw_version =~ "A" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", extra:"Hardware revision: " + hw_version );
  security_message( port:0, data:report );
  exit( 0 );
} else #nb: Other revisions
  exit( 99 );

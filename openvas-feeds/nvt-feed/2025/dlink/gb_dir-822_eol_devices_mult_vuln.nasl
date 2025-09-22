# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-860l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171555");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-24 08:13:59 +0000 (Tue, 24 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-08 13:34:49 +0000 (Mon, 08 Aug 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2018-19987",
                "CVE-2022-27255",
                "CVE-2024-25331",
                "CVE-2024-34950"
               );

  script_name("D-Link DIR-822 Multiple Vulnerabilities (2018 - 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-822 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-19987: Command injection via IsAccessPoint in /HNAP1/SetAccessPointMode

  - CVE-2022-27255: Stack-based buffer overflow vulnerability in the Realtek Device eCOS RTL819x
  Chipset Family Software

  - No CVE: Reflected XSS

  - CVE-2024-25331: LAN-Side Unauthenticated Remote Code Execution (RCE) vulnerability elevated
  from HNAP Stack-Based Buffer Overflow

  - CVE-2024-34950: Stack-based buffer overflow vulnerability in the SetNetworkTomographySettings
  function");

  script_tag(name:"affected", value:"D-Link DIR-822 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-822 Rev. Ax and Bx devices reached End-of-Support Date in 2018,
  and Rev. Cx and Ex in 2024, they are no longer supported, and firmware development has ceased.
  See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10303");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10372");
  script_xref(name:"URL", value:"https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990");
  script_xref(name:"URL", value:"https://dear-sunshine-ba5.notion.site/D-Link-DIR-822-v1-0-5-Stack-Overflow-e77ff3d9c31f4a98bfa0fa71eca54000");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-815_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171551");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-23 14:21:08 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-20 10:15:22 +0000 (Fri, 20 Jun 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2024-22651",
                "CVE-2025-6328"
               );

  script_name("D-Link DIR-815 Multiple Vulnerabilities (2024 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-815 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-22651: Command injection vulnerability in the ssdpcgi_main function of cgibin binary

  - CVE-2025-6328: Stack-based buffer overflow

  - No CVE: Reflected XSS

  - No CVE: Flaw in the LAN-side device's web configuration feature getcfg.php");

  script_tag(name:"affected", value:"D-Link DIR-815 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-815 Rev. Ax, Bx and Cx devices reached End-of-Support Date in 2019,
  and Rev. Dx in 2024, they are no longer supported, and firmware development has ceased.
  See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://www.dlinkmea.com/index.php/product/details?det=UTNVaUZ5aE5Tczh1K0owMjZCcVN3dz09");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10190");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10261");
  script_xref(name:"URL", value:"https://github.com/goldds96/Report/blob/main/DLink/DIR-815/CI.md");
  script_xref(name:"URL", value:"https://github.com/Thir0th/Thir0th-CVE/blob/main/D-Link%20DIR-815%20RevA%20v1.01.md");
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

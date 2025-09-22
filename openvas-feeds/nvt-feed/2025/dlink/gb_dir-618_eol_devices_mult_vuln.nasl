# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-618_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171338");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-03-26 07:55:19 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 18:42:50 +0000 (Tue, 15 Jul 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2025-2546",
                "CVE-2025-2547",
                "CVE-2025-2548",
                "CVE-2025-2549",
                "CVE-2025-2550",
                "CVE-2025-2551",
                "CVE-2025-2552",
                "CVE-2025-2553"
               );

  script_name("D-Link DIR-618 Multiple Vulnerabilities (2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-618 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-2546, CVE-2025-2547, CVE-2025-2548, CVE-2025-2549, CVE-2025-2550, CVE-2025-2551,
  CVE-2025-2552, CVE-2025-2553: Multiple improper access control vulnerabilities at various pages
  under the /goform/ directory.");

  script_tag(name:"affected", value:"D-Link DIR-618 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for DIR-618 has ended in 01.06.2018, therefore
  most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formAdvFirewall-1b053a41781f801ca1a5e09bb83a22c5?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formAdvNetwork-1b053a41781f8085a4e8d3c1d1de5f56?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formSetDomainFilter-1b053a41781f80ffa989c54c391636f6?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formSetPassword-1b053a41781f8021b704f7dfeb1fcd09?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formSetDDNS-1b053a41781f80659702da9a589e4f4a?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formSetPortTr-1b053a41781f8000a9ded17aa2f587cc?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formTcpipSetup-1b053a41781f80fbbf94fda0c3b5ebfa?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-618-formVirtualServ-1b053a41781f80b28443daabf03c0825?pvs=4");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

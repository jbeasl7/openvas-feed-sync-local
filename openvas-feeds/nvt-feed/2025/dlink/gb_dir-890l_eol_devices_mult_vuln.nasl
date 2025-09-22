# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-890l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171500");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-13 19:57:15 +0000 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 20:25:29 +0000 (Tue, 13 May 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2022-29778",
                "CVE-2022-30521",
                "CVE-2023-30063",
                "CVE-2025-4340",
                "CVE-2025-8231"
               );

  script_name("D-Link DIR-890L Multiple Vulnerabilities (2023 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-890L devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-29778: Remote code execution due to the hardcoded option Wake-On-Lan for the parameter
  'descriptor' at SetVirtualServerSettings.php

  - CVE-2022-30521: Stack-based Buffer Overflow

  - CVE-2023-30063: Authentication bypass

  - CVE-2025-4340: Command injection

  - CVE-2025-8231: Hardcoded UART credentials");

  script_tag(name:"affected", value:"D-Link DIR-890L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for DIR-890L has ended in 01.01.2020, therefore
  most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://github.com/TyeYeah/DIR-890L-1.20-RCE");
  script_xref(name:"URL", value:"https://github.com/winmt/CVE/blob/main/DIR-890L/README.md");
  script_xref(name:"URL", value:"https://github.com/Zarathustra-L/IoT_Vul/tree/main/D-Link/DIR-890L/Auth%20bypass");
  script_xref(name:"URL", value:"https://github.com/CH13hh/tmp_store_cc/blob/main/tt/1.md");
  script_xref(name:"URL", value:"https://github.com/Nicholas-wei/bug-discovery/blob/main/dlink/dir890-hardcoded/dir890-hardcoded.md");
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

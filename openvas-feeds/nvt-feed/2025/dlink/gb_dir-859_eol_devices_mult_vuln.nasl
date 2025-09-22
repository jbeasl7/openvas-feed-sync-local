# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-859_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171561");
  script_version("2025-06-27T15:42:32+0000");
  script_tag(name:"last_modification", value:"2025-06-27 15:42:32 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-26 12:40:37 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 08:15:07 +0000 (Sun, 21 Jan 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2019-17508",
                "CVE-2020-25506",
                "CVE-2022-25106",
                "CVE-2022-46476",
                "CVE-2024-48630",
                "CVE-2023-36092",
                "CVE-2024-0769",
                "CVE-2024-57045"
               );

  script_name("D-Link DIR-859 Multiple Vulnerabilities (2019 - 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-859 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-17508: Command injection via the $SERVER variable in /etc/services/DEVICE.TIME.php

  - CVE-2020-25506: Command injection vulnerability

  - CVE-2022-25106: Stack-based buffer overflow via the function genacgi_main

  - CVE-2022-46476: Command injection vulnerability via the service variable in the soapcgi_main
  function

  - CVE-2023-36092: Authentication bypass vulnerability

  - CVE-2024-0769: Path traversal via the service argument in the /hedwig.cgi

  - CVE-2024-57045: An attacker can obtain a user name and password by forging a post request to
  the / getcfg.php page");

  script_tag(name:"affected", value:"D-Link DIR-859 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-859 devices reached End-of-Support Date in 10.12.2020, they are no
  longer supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10344");
  script_xref(name:"URL", value:"https://unit42.paloaltonetworks.com/mirai-variant-iot-vulnerabilities/");
  script_xref(name:"URL", value:"https://github.com/dahua966/Routers-vuls/tree/master/DIR-859");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10267");
  script_xref(name:"URL", value:"https://github.com/Insight8991/iot/blob/main/dir859%20Command%20Execution%20Vulnerability.md");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10371");
  script_xref(name:"URL", value:"https://github.com/c2dc/cve-reported/blob/main/CVE-2024-0769/CVE-2024-0769.md");
  script_xref(name:"URL", value:"https://github.com/Shuanunio/CVE_Requests/blob/main/D-Link/DIR-859/ACL%20bypass%20Vulnerability%20in%20D-Link%20DIR-859.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-818lw_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113451");
  script_version("2025-08-19T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"creation_date", value:"2019-07-31 12:01:18 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-10 13:16:35 +0000 (Wed, 10 Aug 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2019-12786",
                "CVE-2019-12787",
                "CVE-2019-13481",
                "CVE-2019-13482",
                "CVE-2022-35619",
                "CVE-2022-35620",
                "CVE-2025-7553",
                "CVE-2025-9003"
                );

  script_name("D-Link DIR-818LW Multiple Vulnerabilities (2019 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-818LW devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-12786: Command injection in HNAP1 SetWanSettings via an XML injection of the value of
  the IPAddress key

  - CVE-2019-12787: Command injection in HNAP1 SetWanSettings via an XML injection of the value of
  the Gateway key

  - CVE-2019-13481: Command injection in HNAP1 (exploitable with authentication) via shell
  metacharacters in the MTU field to SetWanSettings

  - CVE-2019-13482: Command injection in HNAP1 (exploitable with authentication) via shell
  metacharacters in the Type field to SetWantSettings

  - CVE-2022-35619: Remote code execution (RCE) vulnerability via the function ssdpcgi_main

  - CVE-2022-35620: Remote code execution (RCE) vulnerability via the function binary.soapcgi_main

  - CVE-2025-7553: OS command injection via manipulation of the argument NTP Server of the System
  Time Page component

  - CVE-2025-9003: XSS in the file /bsc_lan.php of the component DHCP Reserved Address Handler");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to gain complete control over the target device.");

  script_tag(name:"affected", value:"D-Link DIR-818LW devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-818LW devices reached End-of-Support Date in 15.12.2019, they are no
  longer supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-3.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/109131");
  script_xref(name:"URL", value:"https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-4.pdf");
  script_xref(name:"URL", value:"https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-2-protected.pdf");
  script_xref(name:"URL", value:"https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-protected.pdf");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170802");
  script_version("2025-05-19T05:40:32+0000");
  script_tag(name:"last_modification", value:"2025-05-19 05:40:32 +0000 (Mon, 19 May 2025)");
  script_tag(name:"creation_date", value:"2024-08-12 20:20:11 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-16 19:11:11 +0000 (Fri, 16 May 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-32136", "CVE-2023-32137", "CVE-2023-32138", "CVE-2023-32139",
                "CVE-2023-32140", "CVE-2023-32141", "CVE-2023-32142", "CVE-2023-32143",
                "CVE-2023-32144", "CVE-2023-32145", "CVE-2023-32146");

  script_name("D-Link DAP-1360 Rev. F / DAP-2020 Rev. A2 Devices Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected", "d-link/dap/hw_version");

  script_tag(name:"summary", value:"D-Link DAP-1360 Rev. F and DAP-2020 Rev. A2 devices are prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-32136 / ZDI-CAN-18414: webproc var:menu stack-based buffer overflow

  - CVE-2023-32137 / ZDI-CAN-18415: webproc WEB_DisplayPage directory traversal

  - CVE-2023-32138 / ZDI-CAN-18416: webproc heap-based buffer overflow

  - CVE-2023-32139 / ZDI-CAN-18417: webproc stack-based buffer overflow

  - CVE-2023-32140 / ZDI-CAN-18418: webproc var:sys_Token heap-based buffer overflow

  - CVE-2023-32141 / ZDI-CAN-18419: webproc WEB_DisplayPage stack-based buffer overflow

  - CVE-2023-32142 / ZDI-CAN-18422: webproc var:page stack-based buffer overflow

  - CVE-2023-32143 / ZDI-CAN-18423: webupg UPGCGI_CheckAuth numeric truncation

  - CVE-2023-32144 / ZDI-CAN-18454: webproc COMM_MakeCustomMsg stack-based buffer overflow

  - CVE-2023-32145 / ZDI-CAN-18455: Hardcoded credentials

  - CVE-2023-32146 / ZDI-CAN-18746: Multiple parameters stack-based buffer overflow");

  script_tag(name:"affected", value:"- D-Link DAP-1360 Rev. F devices prior to version
  6.15EUb01

  - D-Link DAP-2020 Rev. A2 devices prior to version 1.03rc004");

  script_tag(name:"solution", value:"- DAP-1360 Rev. F devices: Update to version 6.15EUb01 or later

  - DAP-2020 Rev. A2 devices: Update to version 1.03rc004 or later");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10324");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-528/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-529/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-530/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-531/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-532/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-533/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-534/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-535/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-536/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-537/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-538/");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dap-1360_firmware",
                      "cpe:/o:dlink:dap-2020_firmware" );

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = infos["version"];

if ( ! hw_version = get_kb_item( "d-link/dap/hw_version" ) )
  exit( 0 );

if ( cpe =~ "dap-1360" && hw_version =~ "^F" ) {
  if ( revcomp( a:version, b:"6.15EUb01" ) < 0 ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"6.15EUb01" );
    security_message( port:0, data:report );
    exit( 0 );
  }
} else if ( cpe =~ "dap-2020" && hw_version =~ "^A2" ) {
  if ( revcomp( a:version, b:"1.03rc004" ) < 0 ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.03rc004" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

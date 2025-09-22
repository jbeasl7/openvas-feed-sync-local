# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-825_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170305");
  script_version("2025-08-19T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"creation_date", value:"2023-02-06 15:32:27 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-09 00:15:47 +0000 (Wed, 09 Jul 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2019-9122",
                "CVE-2020-10213",
                "CVE-2020-10214",
                "CVE-2020-10215",
                "CVE-2020-10216",
                "CVE-2024-57595",
                "CVE-2025-6291",
                "CVE-2025-6292",
                "CVE-2025-7206",
                "CVE-2025-8949"
               );

  script_name("D-Link DIR-825 Rev B Multiple Vulnerabilities (2019 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-825 Rev. B devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-9122: D-Link DIR-825 Rev.B devices allow remote attackers to execute
  arbitrary commands via the ntp_server parameter in an ntp_sync.cgi POST request.

  - CVE-2020-10213: command injection vulnerability via POST request to set_sta_enrollee_pin.cgi

  - CVE-2020-10214: command injection vulnerability via POST request to ntp_sync.cgi

  - CVE-2020-10215: command injection vulnerability via POST request to dns_query.cgi

  - CVE-2020-10216: command injection vulnerability via POST request to system_time.cgi

  - CVE-2024-57595: command injection vulnerability in the CGl interface apc_client_pin.cgi

  - CVE-2025-6291, CVE-2025-6292, CVE-2025-7206, CVE-2025-8949: Stack-based buffer overflow
  vulnerabilities");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev B devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  The DIR-825 revision B model has entered the end-of-life process by the time these vulnerabilities
  were disclosed and therefore the vendor is unable to provide support or development to mitigate
  them.");

  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability1.md");
  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability2.md");
  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability3.md");
  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability4.md");
  script_xref(name:"URL", value:"https://github.com/IdaJea/IOT_vuln_1/blob/master/DIR825/wps_pin.md");
  script_xref(name:"URL", value:"https://github.com/xiaobor123/vul-finds/tree/main/vul-find-dir825-dlink");
  script_xref(name:"URL", value:"https://github.com/xiaobor123/vul-finds/tree/main/vul-find-dir825-dlink-sub_4091AC");
  script_xref(name:"URL", value:"https://github.com/i-Corner/cve/issues/2");
  script_xref(name:"URL", value:"https://github.com/i-Corner/cve/issues/16");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( ! hw_version = get_kb_item( "d-link/dir/hw_version" ) )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( hw_version =~ "B" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location, extra:"Hardware revision: " + hw_version );
  security_message( port:port, data:report );
  exit( 0 );
}

#nb: Revisions like Gx, Rx are not affected
exit( 99 );

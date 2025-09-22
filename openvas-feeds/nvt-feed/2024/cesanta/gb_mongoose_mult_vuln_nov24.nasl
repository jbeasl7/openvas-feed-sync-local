# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cesanta:mongoose";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131349");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-12-04 12:41:54 +0000 (Wed, 04 Dec 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-19 17:55:22 +0000 (Tue, 19 Nov 2024)");

  script_cve_id("CVE-2024-42383", "CVE-2024-42384", "CVE-2024-42385", "CVE-2024-42386",
                "CVE-2024-42387", "CVE-2024-42388", "CVE-2024-42389", "CVE-2024-42390",
                "CVE-2024-42391", "CVE-2024-42392");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Cesanta Mongoose Web Server 7.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_mongoose_web_server_http_detect.nasl");
  script_mandatory_keys("cesanta/mongoose/detected");

  script_tag(name:"summary", value:"Cesanta Mongoose Web Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-42383: Cesanta Mongoose Web Server allows to write a NULL byte value beyond the memory
  space dedicated for the hostname field.

  - CVE-2024-42384, CVE-2024-42386: Cesanta Mongoose Web Server allows an attacker to send an
  unexpected TLS packet and produce a segmentation fault on the application.

  - CVE-2024-42385: Cesanta Mongoose Web Server allows to trigger an out-of-bound memory write if
  the PEM certificate contains unexpected characters.

  - CVE-2024-42387, CVE-2024-42388, CVE-2024-42389, CVE-2024-42390, CVE-2024-42391: Cesanta
  Mongoose Web Server allows an attacker to send an unexpected TLS packet and force the application
  to read unintended heap memory space.

  - CVE-2024-42392: Cesanta Mongoose Web Server allows to trigger an infinite loop bug if the input
  string contains unexpected characters.");

  script_tag(name:"affected", value:"Mongoose Web Server probably version 7.14 only.");

  script_tag(name:"solution", value:"No known solution is available as of 04th December, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42383");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42384");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42385");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42386");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42387");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42388");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42389");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42390");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42391");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42392");
  script_xref(name:"URL", value:"https://www.nozominetworks.com/labs/vulnerability-advisories-cve-2024-42393");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version: version, test_version: "7.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 0 );


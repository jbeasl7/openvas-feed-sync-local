# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113670");
  script_version("2024-09-03T06:26:22+0000");
  script_tag(name:"last_modification", value:"2024-09-03 06:26:22 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2020-04-07 07:48:50 +0000 (Tue, 07 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-06 12:34:00 +0000 (Mon, 06 Apr 2020)");

  script_cve_id("CVE-2020-8637", "CVE-2020-8638", "CVE-2020-8639", "CVE-2020-12273",
                "CVE-2020-12274", "CVE-2024-42906");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TestLink <= 1.9.20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_testlink_http_detect.nasl");
  script_mandatory_keys("testlink/detected");

  script_tag(name:"summary", value:"TestLink is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-8637: SQL injection (SQLi) in dragdroptreenodes.php via the node_id parameter

  - CVE-2020-8638: SQL injection (SQLi) in planUrgency.php via the urgency parameter

  - CVE-2020-8639: Arbitrary code execution due to unrestricted file uploads in keywordsImport.php

  - CVE-2020-12273: A crafted login.php viewer parameter exposes cleartext credentials

  - CVE-2020-12274: The lib/cfields/cfieldsExport.php goback_url parameter causes a security risk
  because it depends on client input and is not constrained to lib/cfields/cfieldsView.php at the
  web site associated with the session.

  - CVE-2024-42906: Reflected cross-site scripting (XSS) within the file upload function.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete
  control over the target system.");

  script_tag(name:"affected", value:"TestLink version 1.9.20 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: Vendor states that, there is not going to be a new release and users should download the
  branch testlink_1_9_20_fixed which addresses those vulnerabilities.");

  script_xref(name:"URL", value:"https://ackcent.com/blog/testlink-1.9.20-unrestricted-file-upload-and-sql-injection/");
  script_xref(name:"URL", value:"http://mantis.testlink.org/view.php?id=8895");
  script_xref(name:"URL", value:"http://mantis.testlink.org/view.php?id=8894");
  script_xref(name:"URL", value:"https://github.com/Alkatraz97/CVEs/blob/main/CVE-2024-42906.md");
  script_xref(name:"URL", value:"https://github.com/TestLinkOpenSourceTRMS/testlink-code/blob/testlink_1_9_20_fixed/CHANGELOG");

  exit(0);
}

CPE = "cpe:/a:testlink:testlink";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"1.9.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

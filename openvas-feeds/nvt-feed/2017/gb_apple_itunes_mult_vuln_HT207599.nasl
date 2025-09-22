# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810724");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2009-3270", "CVE-2009-3560", "CVE-2009-3720", "CVE-2012-1147",
                "CVE-2012-1148", "CVE-2012-6702", "CVE-2013-7443", "CVE-2015-1283",
                "CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416", "CVE-2015-3717",
                "CVE-2015-6607", "CVE-2016-0718", "CVE-2016-4472", "CVE-2016-5300",
                "CVE-2016-6153", "CVE-2017-2383", "CVE-2017-2463", "CVE-2017-2479",
                "CVE-2017-2480", "CVE-2017-5029");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:05:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2017-03-30 17:37:29 +0530 (Thu, 30 Mar 2017)");
  script_name("Apple iTunes Multiple Vulnerabilities (HT207599) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - a client certificate was sent in plaintext. This issue was addressed through improved
  certificate handling.

  - multiple issues existed in SQLite

  - multiple issues existed in expat

  - multiple memory corruption issues were addressed through improved memory handling

  - processing maliciously crafted web content may lead to arbitrary code execution

  - processing maliciously crafted web content may exfiltrate data cross-origin");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code, cause unexpected application termination and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.6 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74228");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.6", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813110");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2018-4101", "CVE-2018-4113", "CVE-2018-4114", "CVE-2018-4117",
                "CVE-2018-4118", "CVE-2018-4119", "CVE-2018-4120", "CVE-2018-4121",
                "CVE-2018-4122", "CVE-2018-4125", "CVE-2018-4127", "CVE-2018-4128",
                "CVE-2018-4129", "CVE-2018-4130", "CVE-2018-4144", "CVE-2018-4146",
                "CVE-2018-4161", "CVE-2018-4162", "CVE-2018-4163", "CVE-2018-4165",
                "CVE-2018-4207", "CVE-2018-4208", "CVE-2018-4209", "CVE-2018-4210",
                "CVE-2018-4212", "CVE-2018-4213");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-02 10:32:52 +0530 (Mon, 02 Apr 2018)");
  script_name("Apple iTunes Security Updates (HT208694) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error due to improper size validation..

  - Multiple memory corruption issues due to improper memory handling.

  - An array indexing issue in the handling of a function in javascript core.

  - A cross-origin issue existed with the fetch API.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will allow remote
  attackers to elevate privileges, exfiltrate data cross-origin, execute arbitrary code and lead to
  a denial of service condition.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.7.4 on Windows");

  script_tag(name:"solution", value:"Update to version 12.7.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208694");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(version_is_less(version:version, test_version:"12.7.4.76")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.7.4.76", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

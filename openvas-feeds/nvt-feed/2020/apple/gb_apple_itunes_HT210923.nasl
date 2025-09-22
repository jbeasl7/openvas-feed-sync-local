# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816615");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2020-3825", "CVE-2020-3826", "CVE-2020-3846", "CVE-2020-3861",
                "CVE-2020-3862", "CVE-2020-3864", "CVE-2020-3865", "CVE-2020-3867",
                "CVE-2020-3868");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-03 21:53:30 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 12:22:35 +0530 (Wed, 29 Jan 2020)");
  script_name("Apple iTunes Security Update (HT210923)");

  script_tag(name:"summary", value:"Apple iTunes is prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper permissions logic.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to gain access to
  protected parts of the file system.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.10.4.");

  script_tag(name:"solution", value:"Update to version 12.10.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210923");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

if(version_is_less(version:version, test_version:"12.10.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.10.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

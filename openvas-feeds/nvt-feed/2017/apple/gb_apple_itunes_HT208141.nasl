# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811879");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2017-13829", "CVE-2017-13831", "CVE-2017-13833", "CVE-2017-5130",
                "CVE-2017-7081", "CVE-2017-7087", "CVE-2017-7090", "CVE-2017-7091",
                "CVE-2017-7092", "CVE-2017-7093", "CVE-2017-7094", "CVE-2017-7095",
                "CVE-2017-7096", "CVE-2017-7098", "CVE-2017-7099", "CVE-2017-7100",
                "CVE-2017-7102", "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7109",
                "CVE-2017-7111", "CVE-2017-7117", "CVE-2017-7120", "CVE-2017-7376",
                "CVE-2017-9049", "CVE-2017-9050", "CVE-2018-4302");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-18 14:22:38 +0000 (Sun, 18 Mar 2018)");
  script_tag(name:"creation_date", value:"2017-10-25 11:53:06 +0530 (Wed, 25 Oct 2017)");
  script_name("Apple iTunes Security Updates (HT208141)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - A permissions issue existed in the handling of web browser cookies.

  - Application Cache policy may be unexpectedly applied.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities will allow
  remote attackers to execute arbitrary code and bypass security.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.7");

  script_tag(name:"solution", value:"Update to version 12.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208141");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100994");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100998");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101005");

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

if(version_is_less(version:version, test_version:"12.7.0.166")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.7.0.166", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

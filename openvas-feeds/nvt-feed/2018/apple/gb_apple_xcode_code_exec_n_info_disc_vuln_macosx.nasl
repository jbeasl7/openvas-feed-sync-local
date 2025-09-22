# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813606");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-11235", "CVE-2018-11233");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-02 00:15:00 +0000 (Sat, 02 May 2020)");
  script_tag(name:"creation_date", value:"2018-06-14 10:59:39 +0530 (Thu, 14 Jun 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Code < 9.4.1 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Apple Xcode is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Git software does not properly validate submodule 'names' supplied via the
    untrusted .gitmodules file when appending them to the '$GIT_DIR/modules'
    directory.

  - An input validation flaw in processing path names on NTFS-based systems to
    read random memory contents.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code and to obtain sensitive information
  that may lead to further attacks.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 9.4.1.");

  script_tag(name:"solution", value:"Update to version 9.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104345");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104346");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"10.13.2"))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"9.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.4.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
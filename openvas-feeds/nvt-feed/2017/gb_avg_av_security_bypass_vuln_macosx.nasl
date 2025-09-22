# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avg:anti-virus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811525");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-9977");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-17 14:59:13 +0530 (Mon, 17 Jul 2017)");
  script_name("AVG AntiVirus < 17.2 Security Bypass Vulnerability - Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_avg_av_detect_macosx.nasl");
  script_mandatory_keys("avg/antivirus/detected");

  script_xref(name:"URL", value:"https://wwws.nightwatchcybersecurity.com/2017/07/06/avg-antivirus-for-macos-doesnt-scan-inside-disk-images-cve-2017-9977/");

  script_tag(name:"summary", value:"AVG AntiVirus is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to AVG AntiVirus for Mac OS X does not scan files
  inside disk images (DMG) files in the on-demand scanner.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  malware detection by leveraging failure to scan inside disk image (aka DMG) files.");

  script_tag(name:"affected", value:"AVG AntiVirus version prior to 17.2 for Mac OS X.");

  script_tag(name:"solution", value:"Update to version 17.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable"); # Note: The issue was fixed in engine version 4668 in October 2016, and was confirmed again in version 17.2, virus database 170626-4. qod is reduced because VT developed considering main antivirus version not the scan engine version.

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"17.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

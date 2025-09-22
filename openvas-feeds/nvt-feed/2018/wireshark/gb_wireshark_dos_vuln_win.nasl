# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112213");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-6836");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-09 15:34:57 +0100 (Fri, 09 Feb 2018)");

  script_name("Wireshark Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The netmonrec_comment_destroy function in wiretap/netmon.c in Wireshark performs a free operation
  on an uninitialized memory address, which allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to cause a denial of service or possible have unspecified other impact.");

  script_tag(name:"affected", value:"Wireshark up to and including version 2.4.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.6.0 or later.");

  script_xref(name:"URL", value:"https://code.wireshark.org/review/#/c/25660/");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14397");
  script_xref(name:"URL", value:"https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=28960d79cca262ac6b974f339697b299a1e28fef");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"2.4.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.6.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

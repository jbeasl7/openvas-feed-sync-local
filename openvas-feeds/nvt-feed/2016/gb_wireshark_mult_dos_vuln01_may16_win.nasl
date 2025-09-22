# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807575");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2016-4084", "CVE-2016-4083", "CVE-2016-4077", "CVE-2016-4076");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-03 11:09:01 +0530 (Tue, 03 May 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (May 2016) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - 'epan/dissectors/packet-ncp2222.inc' script in the NCP dissector does not
    properly initialize memory for search patterns.

  - 'epan/reassemble.c' script in TShark relies on incorrect special-case
    handling of truncated Tvb data structures.

  - 'epan/dissectors/packet-mswsp.c' script in the MS-WSP dissector does not
    ensure that data is available before array allocation.

  - An integer signedness error in 'epan/dissectors/packet-mswsp.c' script in
    the MS-WSP dissector");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.0.x before 2.0.3
  on Windows.");

  script_tag(name:"solution", value:"Update to version 2.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-27.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-20.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-19.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.0.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

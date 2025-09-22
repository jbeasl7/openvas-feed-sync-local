# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811072");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2017-9348", "CVE-2017-9347", "CVE-2017-9353");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-20 12:29:00 +0000 (Wed, 20 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-06-02 16:48:52 +0530 (Fri, 02 Jun 2017)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-02 (Jun 2017) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the epan/dissectors/packet-ipv6.c script within the IPv6
    dissector which could crash.

  - An error in the epan/dissectors/asn1/ros/packet-ros-template.c script within
    the ROS dissector which could crash with a NULL pointer dereference.

  - An error in the epan/dissectors/packet-dof.c script within the DOF dissector
    which could read past the end of a buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to crash wireshark and result in denial-of-service condition.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.6
  on Windows.");

  script_tag(name:"solution", value:"Update to version 2.2.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-23.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98805");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-31.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-33.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^2\.2" && version_is_less(version:vers, test_version:"2.2.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.2.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

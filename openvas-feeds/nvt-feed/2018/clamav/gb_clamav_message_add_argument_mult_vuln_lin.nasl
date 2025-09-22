# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812510");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-01-29 13:19:21 +0530 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377",
                "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV <= 0.99.2 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - CVE-2017-12374, CVE-2017-12375: Lack of input validation checking mechanisms during certain mail
  parsing operations and functions.

  - CVE-2017-12376: Improper input validation checking mechanisms when handling Portable Document
  Format (.pdf) files sent to an affected device.

  - CVE-2017-12377: Improper input validation checking mechanisms in mew packet files sent to an
  affected device.

  - CVE-2017-12378: Improper input validation checking mechanisms of '.tar' (Tape Archive) files
  sent to an affected device.

  - CVE-2017-12379: Improper input validation checking mechanisms in the message parsing function on
  an affected system.

  - CVE-2017-12380: Improper input validation checking mechanisms during certain mail parsing
  functions of the ClamAV software.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause a
  denial of service and potentially execute arbitrary code on the affected device.");

  script_tag(name:"affected", value:"ClamAV version 0.99.2 and prior.");

  script_tag(name:"solution", value:"Update to version 0.99.3 or later.");

  script_xref(name:"URL", value:"http://blog.clamav.net/2018/01/clamav-0993-has-been-released.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "0.99.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.99.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quagga:quagga";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140461");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-01 12:34:31 +0700 (Wed, 01 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-18 16:16:00 +0000 (Sat, 18 Nov 2017)");

  script_cve_id("CVE-2017-16227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Quagga DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_quagga_remote_detect.nasl");
  script_mandatory_keys("quagga/installed");

  script_tag(name:"summary", value:"Quagga is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The aspath_put function in bgpd/bgp_aspath.c in Quagga allows remote
  attackers to cause a denial of service (session drop) via BGP UPDATE messages, because AS_PATH size calculation
  for long paths counts certain bytes twice and consequently constructs an invalid message.");

  script_tag(name:"affected", value:"Quagga prior version 1.2.2.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_xref(name:"URL", value:"https://lists.quagga.net/pipermail/quagga-dev/2017-September/033284.html");
  script_xref(name:"URL", value:"https://ftp.cc.uoc.gr/mirrors/nongnu.org/quagga/quagga-1.2.2.changelog.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:extremenetworks:exos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106425");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_cve_id("CVE-2016-0777", "CVE-2016-0778");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Extreme ExtremeXOS OpenSSH Vulnerabilities (VN-2016-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_extremeos_consolidation.nasl");
  script_mandatory_keys("extreme/exos/detected");

  script_tag(name:"summary", value:"Extreme ExtremeXOS is prone to multiple OpenSSH
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Roaming is enabled by default in the OpenSSH client, and
  contains two vulnerabilities that can be exploited by a malicious SSH server (or a trusted but
  compromised server):

  - CVE-2016-0777: An information leak (memory disclosure)

  - CVE-2016-0778: A buffer overflow (heap-based).");

  script_tag(name:"impact", value:"An attacker may obtain sensitive information or cause a denial
  of service condition.");

  script_tag(name:"affected", value:"Extreme ExtremeXOS version 15.7 and later.");

  script_tag(name:"solution", value:"Update to version 15.7.3 Patch 1-8, 16.2.1, 16.1.3, 22.1.1 or
  later.");

  script_xref(name:"URL", value:"https://gtacknowledge.extremenetworks.com/articles/Vulnerability_Notice/VN-2016-001-OpenSSH");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "15.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.7.3 Patch 1-8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^15\.7\.3") {
  patch = get_kb_item("extreme/exos/patch");
  if (!patch || version_is_less(version: patch, test_version: "1.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.7.3 Patch 1-8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version_is_greater(version: version, test_version: "16.1.1") &&
    version_is_less(version: version, test_version: "16.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.1.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_greater(version: version, test_version: "21.1.1") &&
    version_is_less(version: version, test_version: "22.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

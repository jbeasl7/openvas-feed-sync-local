# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:fortinet:fortios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105727");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-05-18 13:18:29 +0200 (Wed, 18 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 14:04:00 +0000 (Tue, 10 Nov 2020)");

  script_cve_id("CVE-2015-5738");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiGate RSA-CRT Key Leak Vulnerability (FG-IR-16-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortigate_consolidation.nasl");
  script_mandatory_keys("fortinet/fortigate/detected");

  script_tag(name:"summary", value:"FortiOS now includes for all SSL libraries a countermeasure
  against Lenstra's fault attack on RSA-CRT optimization when a RSA signature is corrupted.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Fortinet FortiGate prior to version 5.0.13 and version 5.2.0
  through 5.2.5, with the SSLVPN web portal feature configured.");

  script_tag(name:"solution", value:"Update to version 5.0.13, 5.2.6, 5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-008");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-008");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2.0", test_version_up: "5.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

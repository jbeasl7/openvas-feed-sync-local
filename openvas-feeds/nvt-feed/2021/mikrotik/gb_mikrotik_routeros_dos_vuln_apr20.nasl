# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145885");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-05-04 05:09:01 +0000 (Tue, 04 May 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-30 13:17:00 +0000 (Fri, 30 Jul 2021)");

  script_cve_id("CVE-2020-20221", "CVE-2020-20247");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.46.5 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-20221: Uncontrolled resource consumption in the /nova/bin/cerm process

  - CVE-2020-20247: Memory corruption in the /nova/bin/traceroute process");

  script_tag(name:"affected", value:"MikroTik RouterOS version 6.46.4 and prior.");

  script_tag(name:"solution", value:"Update to version 6.46.5 (long-term version) or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2020/May/30");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2021/May/1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.46.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.46.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

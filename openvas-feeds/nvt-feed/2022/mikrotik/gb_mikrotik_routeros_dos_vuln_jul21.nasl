# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124148");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-08-29 15:35:22 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 19:19:00 +0000 (Thu, 01 Sep 2022)");

  script_cve_id("CVE-2022-36522");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS DoS Vulnerability (CVE-2022-36522)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mikrotik RouterOs was discovered to contain an assertion
  failure in the component /advanced-tools/nova/bin/netwatch. This vulnerability allows attackers
  to cause a Denial of Service (DoS) via a crafted packet.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.49.6.");

  script_tag(name:"solution", value:"Update to version 6.49.6 or later.");

  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2022-36522/README.md");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2021/Jul/0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.49.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

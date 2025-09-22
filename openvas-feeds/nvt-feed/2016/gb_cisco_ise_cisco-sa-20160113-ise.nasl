# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105510");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-01-14 13:21:12 +0100 (Thu, 14 Jan 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:19:00 +0000 (Wed, 07 Dec 2016)");

  script_cve_id("CVE-2015-6323");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Unauthorized Access Vulnerability (cisco-sa-20160113-ise)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"A vulnerability in the Admin portal of devices running Cisco
  Identity Services Engine (ISE) software could allow an unauthenticated, remote attacker to gain
  unauthorized access to an affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who can connect to the Admin portal of an affected
  device could potentially exploit this vulnerability.");

  script_tag(name:"impact", value:"A successful exploit may result in a complete compromise of the
  affected device.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-ise");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

patch = get_kb_item("cisco/ise/patch");

# version is for example 1.1.4.218. But for this check we need only 1.1.4
v = split(version, sep: ".", keep: FALSE);
version = v[0] + "." + v[1] + "." + v[2];

if (version_is_less(version: version, test_version: "1.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version == "1.2.0") {
  if (!patch || version_is_less(version: patch, test_version: "17")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "1.2.0", fixed_patch: 17);
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version == "1.2.1") {
  if (!patch || version_is_less(version: patch, test_version: "8")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "1.2.1", fixed_patch: 8);
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version == "1.3.0") {
  if (!patch || version_is_less(version: patch, test_version: "5")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "1.3.0", fixed_patch: 5);
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version == "1.4.0") {
  if (!patch || version_is_less(version: patch, test_version: "4")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "1.4.0", fixed_patch: 4);
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

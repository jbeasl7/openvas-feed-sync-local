# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105524");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-01-20 12:43:15 +0100 (Wed, 20 Jan 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:19:00 +0000 (Wed, 07 Dec 2016)");

  script_cve_id("CVE-2015-6317");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Unauthorized Access Vulnerability (cisco-sa-20160113-ise2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"Cisco Identity Services Engine versions prior to 2.0 contain a
  vulnerability that could allow a low-privileged authenticated, remote attacker to access specific
  web resources that are designed to be accessed only by higher-privileged administrative users.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability occurs because specific types of web
  resources are not correctly filtered for administrative users with different privileges. An
  attacker could exploit this vulnerability by authenticating at a low-privileged account and then
  accessing the web resources directly.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to access web pages that are
  reserved for higher-privileged administrative users.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-ise2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

patch = get_kb_item("cisco/ise/patch");

if (version_is_less(version: version, test_version: "1.4.0.253")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0 / 1.4.0.253 Patch 5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.4.0.253")) {
  if (!patch || version_is_less(version: patch, test_version: "5")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "2.0 / 1.4.0.253 Patch 5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106451");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-08 15:34:12 +0700 (Thu, 08 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 18:18:00 +0000 (Thu, 22 Dec 2016)");

  script_cve_id("CVE-2016-9198");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Active Directory Integration Component Denial of Service Vulnerability (cisco-sa-20161207-ise)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"A vulnerability in the Active Directory integration component
  of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to
  perform a denial of service (DoS) attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of Password
  Authentication Protocol (PAP) authentication requests when ISE is configured with an
  authorization policy based on Active Directory group membership. An attacker could exploit this
  vulnerability by crafting a special but formally correct PAP authentication request that will
  trigger the issue.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause all subsequent
  authentication requests for the same Active Directory domain to fail.");

  script_tag(name:"affected", value:"Cisco Identity Services Engine software release 1.2.1.199.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-ise");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_equal(version: version, test_version: "1.2.1.199")) {
  report = report_fixed_ver(installed_version: version, fixed_version: 'See advisory');
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:content_security_management_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140309");
  script_cve_id("CVE-2017-6783");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("2025-09-11T05:38:37+0000");

  script_name("Cisco Content Security Management Appliance SNMP Polling Information Disclosure Vulnerability (cisco-sa-20170816-csa)");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170816-csa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in SNMP polling for the Cisco Content Security Management
  Appliance (SMA) could allow an authenticated, remote attacker to discover confidential information about the
  appliances that should be available only to an administrative user.");

  script_tag(name:"insight", value:"The vulnerability occurs because the appliances do not protect confidential
  information at rest in response to Simple Network Management Protocol (SNMP) poll requests. An attacker could
  exploit this vulnerability by doing a crafted SNMP poll request to the targeted security appliance.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to discover confidential information that
  should be restricted, and the attacker could use this information to conduct additional reconnaissance. The
  attacker must know the configured SNMP community string to exploit this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-25 10:50:00 +0000 (Fri, 25 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-08-17 10:41:27 +0700 (Thu, 17 Aug 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_csma_consolidation.nasl");
  script_mandatory_keys("cisco_csm/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version == "10.1.0-037") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

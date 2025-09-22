# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106189");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-19 08:44:32 +0700 (Fri, 19 Aug 2016)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-1365");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Application Policy Infrastructure Controller Enterprise Module Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_apic_em_web_detect.nasl");
  script_mandatory_keys("cisco/apic_em/version");

  script_tag(name:"summary", value:"A vulnerability in the Grapevine update process of the Cisco Application
Policy Infrastructure Controller Enterprise Module (APIC-EM) could allow an authenticated, remote attacker
to execute arbitrary commands on the underlying operating system with the privileges of the root user.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input sanitization during
the Grapevine update process. An attacker could exploit this vulnerability by authenticating to the affected
system with administrative privileges and inserting arbitrary commands into an upgrade parameter.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary commands on
the affected system with root-level privileges.");

  script_tag(name:"affected", value:"Cisco APIC-EM software release 1.0.");

  script_tag(name:"solution", value:"Cisco has released free software updates that address the vulnerability.
Check the advisory for further details.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-apic");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version == "1.0.10") {
  report = report_fixed_ver(installed_version: version, fixed_version: 'See vendor advisory.');
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:puppet:enterprise";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106363");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-11-01 10:57:40 +0700 (Tue, 01 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-10 15:40:00 +0000 (Wed, 10 Jul 2019)");

  script_cve_id("CVE-2016-5714", "CVE-2016-5715", "CVE-2016-5716");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Puppet Enterprise < 2016.4.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_puppet_enterprise_consolidation.nasl");
  script_mandatory_keys("puppet/enterprise/detected");

  script_tag(name:"summary", value:"Puppet Enterprise is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-5714: Unprivileged access to environment catalogs which may reveal sensitive information
  about your infrastructure if you are using Application Orchestration

  - CVE-2016-5716: Remote code execution because of unsafe string reads

  - Puppet Communications Protocol (PCP) broker string validation vulnerability

  - CVE-2016-5715: Arbitrary URL redirection in Puppet Enterprise Console

  - Puppet Execution Protocol (PXP) command whitelist validation vulnerability");

  script_tag(name:"impact", value:"An attacker may execute remote code, obtain sensitive information
  or use it for phishing attacks.");

  script_tag(name:"affected", value:"Puppet Enterprise prior to version 2016.4.0.");

  script_tag(name:"solution", value:"Update to version 2016.4.0 or later.");

  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2016-5714");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/pe-console-oct-2016");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/pcp-broker-oct-2016");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2016-5715");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/pxp-agent-oct-2016");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2016.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2016.4.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

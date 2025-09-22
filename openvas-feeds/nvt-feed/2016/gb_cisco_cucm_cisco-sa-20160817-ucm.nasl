# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106190");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-08-19 10:22:15 +0700 (Fri, 19 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-12 19:49:00 +0000 (Mon, 12 Dec 2016)");

  script_cve_id("CVE-2016-6364");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager Information Disclosure Vulnerability (cisco-sa-20160817-ucm)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_consolidation.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_tag(name:"summary", value:"A vulnerability in the User Data Services (UDS) Application
  Programming Interface (API) for Cisco Unified Communications Manager could allow an
  unauthenticated, remote attacker to view confidential information that should require
  authentication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper authentication controls
  for certain information returned by the UDS API. An attacker could exploit this vulnerability by
  accessing the UDS API.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to view certain information
  that is confidential and should require authentication to retrieve via the UDS API.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager version 11.5.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-ucm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = str_replace(string: version, find: "-", replace: ".");

if (version == "11.5.0.98000.486") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See vendor advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

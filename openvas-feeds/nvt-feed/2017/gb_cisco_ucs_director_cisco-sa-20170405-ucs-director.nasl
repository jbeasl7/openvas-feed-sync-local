# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:ucs_director";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106726");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-07 11:22:10 +0200 (Fri, 07 Apr 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-3817");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco UCS Director Virtual Machine Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_ucs_director_consolidation.nasl");
  script_mandatory_keys("cisco/ucs_director/detected");

  script_tag(name:"summary", value:"A vulnerability in the role-based resource checking functionality of Cisco
  Unified Computing System (UCS) Director could allow an authenticated, remote attacker to view unauthorized
  information for any virtual machine in a UCS domain.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper role-based user checks. An attacker
  could exploit this vulnerability by executing certain fenced container commands on an affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to gain unauthorized access to
  virtual machines in a local UCS domain of the affected system.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ucs-director");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

affected = make_list(
  '5.5.0.1',
  '6.0.0.0');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

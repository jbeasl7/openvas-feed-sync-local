# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106640");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-03-13 11:35:28 +0700 (Mon, 13 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:58:42 +0000 (Thu, 25 Jul 2024)");

  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability (cisco-sa-20170310-struts2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"Cisco ISE is prone to a vulnerability in Apache Struts2.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On March 6, 2017, Apache disclosed a vulnerability in the
  Jakarta multipart parser used in Apache Struts2 that could allow an attacker to execute commands
  remotely on the targeted system using a crafted Content-Type header value.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170310-struts2");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list("1.2.0.899",
                     "1.3.0.876",
                     "1.4.0.253",
                     "2.0.0.306",
                     "2.2.0.470",
                     "2.0.1.130",
                     "2.1.0.474",
                     "2.2.0.471");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

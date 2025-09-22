# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_communications_manager_im_and_presence_service";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106453");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-12-08 15:34:12 +0700 (Thu, 08 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-05 13:41:00 +0000 (Thu, 05 Jan 2017)");

  script_cve_id("CVE-2016-6464");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager IM and Presence Service Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_cucmim_version.nasl");
  script_mandatory_keys("cisco/cucmim/version");

  script_tag(name:"impact", value:"An exploit could allow the attacker to view web pages that should have been
restricted.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper input validation performed on
the HTTP packet header. An attacker could exploit this vulnerability by sending a crafted packet to the targeted
device.");

  script_tag(name:"solution", value:"See the vendors advisory for solutions.");

  script_tag(name:"summary", value:"A vulnerability in the web management interface of the Cisco Unified
Communications Manager IM and Presence Service could allow an unauthenticated, remote attacker to view
information on web pages that should be restricted.");

  script_tag(name:"affected", value:"Versions 10.5(1), 10.5(2), 11.0(1) and 11.5(1)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-ucm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

# For example: 10.0.1.10000-26
version = str_replace( string:version, find:"-", replace:"." );

if (version =~ "^10\.5\.1") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See vendor advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^10\.5\.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See vendor advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^11\.0\.1") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See vendor advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^11\.5\.1") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See vendor advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:iox";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106692");
  script_cve_id("CVE-2017-3852");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco Application-Hosting Framework Arbitrary File Creation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-iox");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 1.2.4.2");

  script_tag(name:"summary", value:"A vulnerability in the Cisco application-hosting framework (CAF) component
of the Cisco IOx application environment could allow an authenticated, remote attacker to write or modify
arbitrary files in the virtual instance running on the affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of user-supplied
application packages. An attacker who can upload a malicious package within Cisco IOx could exploit the
vulnerability to modify arbitrary files.");

  script_tag(name:"impact", value:"The impacts of a successful exploit are limited to the scope of the virtual
instance and do not impact the router that is hosting Cisco IOx.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-23 09:56:15 +0700 (Thu, 23 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_iox_web_detect.nasl");
  script_mandatory_keys("cisco_iox/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "www"))
  exit(0);

if (version == '1.1.0.0' || version == '1.0.0.0') {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.4.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);


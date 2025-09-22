# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_communications_manager_im_and_presence_service";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106169");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-05 10:51:26 +0700 (Fri, 05 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-1466");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager IM and Presence Service SIP Packet Processing Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_cucmim_version.nasl");
  script_mandatory_keys("cisco/cucmim/version");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may cause the Cisco SIP Proxy Daemon
  (sipd) process to restart unexpectedly, resulting in a denial of service (DoS) condition on a targeted system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper input validation of SIP packet
  headers. An attacker could exploit this vulnerability by sending a crafted SIP packet to a targeted system.
  A successful exploit could allow the attacker to cause the sipd process to restart unexpectedly, resulting
  in a DoS condition on the system. If the sipd process restarts repeatedly, a successful exploit could also
  result in a sustained DoS condition and cause high disk utilization due to a large number of sipd core files
  being written to disk, which could exacerbate the DoS condition.");

  script_tag(name:"solution", value:"Cisco has released software updates that address this vulnerability.
  There are no workarounds that address this vulnerability.");

  script_tag(name:"summary", value:"A vulnerability in Session Initiation Protocol (SIP) processing functions
  of the Cisco Unified Communications Manager Instant Messaging (IM) and Presence Service could allow an
  unauthenticated, remote attacker to cause the Cisco SIP Proxy Daemon (sipd) process to restart unexpectedly,
  resulting in a denial of service (DoS) condition on a targeted system.");

  script_tag(name:"affected", value:"Versions 9.1(1) SU6, 9.1(1) SU6a, 9.1(1) SU7, 10.5(2) SU2, 10.5(2) SU2a,
  11.0(1) SU1, and 11.5(1).");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-ucm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

# For example: 10.0.1.10000-26
version = str_replace(string: version, find: "-", replace: ".");

if (version =~ "^9\.1\.1") {
  if (version_is_less_equal(version: version, test_version: "9.1.1.91900.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See Advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^10\.5\.2") {
  if (version_is_less_equal(version: version, test_version: "10.5.2.23900.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See Advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^11\.0\.1") {
  if (version_is_less_equal(version: version, test_version: "11.0.1.11900.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See Advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^11\.5\.1") {
  if (version_is_less(version: version, test_version: "11.5.1.11000.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See Advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

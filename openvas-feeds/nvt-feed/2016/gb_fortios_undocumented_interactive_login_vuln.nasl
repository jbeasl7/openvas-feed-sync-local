# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105507");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-13 11:43:18 +0100 (Wed, 13 Jan 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-15 15:42:00 +0000 (Fri, 15 Jul 2016)");

  script_cve_id("CVE-2016-1909");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiOS SSH Undocumented Interactive Login Vulnerability (FG-IR-16-001) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("forti/FortiOS/version");

  script_tag(name:"summary", value:"An undocumented account used for communication with authorized
  FortiManager devices exists on some versions of FortiOS.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On vulnerable versions, and provided 'Administrative Access'
  is enabled for SSH, this account can be used to log in via SSH in Interactive-Keyboard mode, using
  a password shared across all devices. It gives access to a CLI console with administrative
  rights.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote console access to
  vulnerable devices with 'Administrative Access' enabled for SSH.");

  script_tag(name:"affected", value:"Fortinet FortiOS version 4.1.0 through 4.1.10, 4.2.0 through
  4.2.15, 4.3.0 through 4.3.16 and 5.0.0 through 5.0.7.");

  script_tag(name:"solution", value:"Update FortiOS to version 4.1.11, 4.2.16, 4.3.17, 5.0.8,
  5.2.0, 5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80581");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-001");

  exit(0);
}

include("version_func.inc");

if (!version = get_kb_item("forti/FortiOS/version"))
  exit(0);

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.16");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.17");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

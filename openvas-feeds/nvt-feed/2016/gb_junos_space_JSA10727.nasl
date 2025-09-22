# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105608");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-04-18 12:53:02 +0200 (Mon, 18 Apr 2016)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)");

  script_cve_id("CVE-2016-1265", "CVE-2015-4748", "CVE-2015-2601", "CVE-2015-2613",
                "CVE-2015-2659", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4749",
                "CVE-2015-2625");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos Space Multiple Vulnerabilities (JSA10727)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Juniper Networks Junos Space is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been addressed in Junos Space
  15.2R1.

  These include cross site scripting (XSS), default passwords, information leak and command
  injection vulnerabilities. These vulnerabilities may potentially allow a remote unauthenticated
  network based attacker with access to Junos Space to execute arbitrary code on Junos Space or
  gain access to devices managed by Junos Space. These vulnerabilities were found during internal
  product testing. These issues have been assigned CVE-2016-1265. Oracle Java runtime was upgraded
  to 1.7.0 update 85 (from 1.7.0 update 79).");

  script_tag(name:"affected", value:"Juniper Networks Junos Space versions prior to 15.1R3 and 15.2
  prior to 15.2R1.");

  script_tag(name:"solution", value:"Update to version 15.1R3, 15.2R1 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10727");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (version =~ "^15\.2")
  fix = "15.2R1";
else
  fix = "15.1R3";

if (check_js_version(ver: version, fix: fix)) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

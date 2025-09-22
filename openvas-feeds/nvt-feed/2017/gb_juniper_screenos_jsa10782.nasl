# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:screenos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106947");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-07-13 14:37:40 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-22 01:29:00 +0000 (Sat, 22 Jul 2017)");

  script_cve_id("CVE-2017-2335", "CVE-2017-2336", "CVE-2017-2337", "CVE-2017-2338", "CVE-2017-2339");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper ScreenOS Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  script_tag(name:"summary", value:"ScreenOS is prone to multiple XSS vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A security researcher testing a Juniper NetScreen Firewall+VPN found
multiple stored cross-site scripting vulnerabilities that could be used to elevate privileges through the
NetScreen WebUI.  A user with the 'security' role can inject HTML/JavaScript content into the management session
of other users including the administrator.  This enables the lower-privileged user to effectively execute
commands with the permissions of an administrator.");

  script_tag(name:"solution", value:"Update to ScreenOS 6.3.0r24 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10782");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

display_version = version;

version = str_replace(string: version, find: "r", replace: ".");
version = str_replace(string: version, find: "-", replace: ".");

display_fix = '6.3.0r24';

if (version_is_less(version: version, test_version: '6.3.0.24')) {
  report = report_fixed_ver(installed_version: display_version, fixed_version: display_fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

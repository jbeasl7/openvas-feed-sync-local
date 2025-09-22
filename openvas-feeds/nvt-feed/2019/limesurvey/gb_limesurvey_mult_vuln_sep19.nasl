# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114131");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-09-16 14:58:36 +0200 (Mon, 16 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-16172", "CVE-2019-16173", "CVE-2019-16178", "CVE-2019-16182",
                "CVE-2019-16174", "CVE-2019-16176", "CVE-2019-16175", "CVE-2019-16177",
                "CVE-2019-16179", "CVE-2019-16180", "CVE-2019-16184", "CVE-2019-16187",
                "CVE-2019-16181", "CVE-2019-16183", "CVE-2019-16185", "CVE-2019-16186");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 3.17.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-16172: Stored XSS for escalating privileges from a low-privileged account to, for
  example, SuperAdmin. The attack uses a survey group in which the title contains JavaScript that is
  mishandled upon group deletion

  - CVE-2019-16173: Reflected XSS for escalating privileges. This occurs in
  application/core/Survey_Common_Action.php

  - CVE-2019-16178: Stored XSS that allows authenticated users with correct permissions to inject
  arbitrary web script or HTML via titles of admin box buttons on the home page

  - CVE-2019-16182: Reflected XSS that allows remote attackers to inject arbitrary web script or
  HTML via extensions of uploaded files

  - CVE-2019-16181: Admin users can mark other users' notifications as read

  - CVE-2019-16183: Admin users can run an integrity check without proper permissions

  - CVE-2019-16185: Admin users can view, update, or delete reserved menu entries without proper
  permissions

  - CVE-2019-16186: Admin users can access the plugin manager without proper permissions

  - CVE-2019-16174: An XML injection vulnerability that allows remote attackers to import specially
  crafted XML files and execute code or compromise data integrity

  - CVE-2019-16176: A path disclosure vulnerability that allows a remote attacker to discover the
  path to the application in the filesystem

  - CVE-2019-16175: A clickjacking vulnerability related to X-Frame-Options SAMEORIGIN not being set
  by default

  - CVE-2019-16177: The database backup uses browser cache, which exposes it entirely

  - CVE-2019-16179: The default configuration does not enforce SSL/TLS usage

  - CVE-2019-16180: A vulnerability that allows remote attackers to bruteforce the login form and
  enumerate usernames when the LDAP authentication method is used

  - CVE-2019-16184: A CSV injection vulnerability that allows survey participants to inject commands
  via their survey responses that will be included in the export CSV file

  - CVE-2019-16187: A vulnerability related to the use of an anti-CSRF cookie without the HttpOnly
  flag, which allows attackers to access a cookie value via a client-side script.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 3.17.14.");

  script_tag(name:"solution", value:"Update to version 3.17.14 or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/blob/115256d4733d7241ec01a3d6dbff04df80ed1d31/docs/release_notes.txt#L49");

  exit(0);
}

CPE = "cpe:/a:limesurvey:limesurvey";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less(version: version, test_version: "3.17.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.17.14", install_path: path);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);

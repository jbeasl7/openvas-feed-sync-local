# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:afterlogic:aurora";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140384");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-09-21 12:49:43 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-22 16:55:00 +0000 (Fri, 22 Sep 2017)");

  script_cve_id("CVE-2017-14597");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("AfterLogic Aurora/Webmail XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_afterlogic_aurora_webmail_detect.nasl");
  script_mandatory_keys("afterlogic_aurora_webmail/detected");

  script_tag(name:"summary", value:"AfterLogic Aurora and WebMail are prone to a cross-site scripting
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AdminPanel in AfterLogic WebMail and Aurora has an XSS via the
txtDomainName field to adminpanel/modules/pro/inc/ajax.php during addition of a domain.");

  script_tag(name:"solution", value:"There is currently no fixed version available. AfterLogic provides
however a temporary fix.");

  script_xref(name:"URL", value:"https://auroramail.wordpress.com/2017/08/28/vulnerability-in-webmailaurora-closed/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "7.7", test_version2: "7.7.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Workaround");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

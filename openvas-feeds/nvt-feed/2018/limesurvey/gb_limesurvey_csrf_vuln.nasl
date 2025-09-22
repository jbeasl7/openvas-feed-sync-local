# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140788");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-02-20 17:01:16 +0700 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-08 15:23:00 +0000 (Thu, 08 Mar 2018)");

  script_cve_id("CVE-2018-1000053");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 3.3.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey contains a Cross ite Request Forgery (CSRF)
  vulnerability.");

  script_tag(name:"insight", value: "Theme Uninstallation can result in CSRF causing LimeSurvey
  admins to delete all their themes, rendering the website unusable. This attack appear to be
  exploitable via Simple HTML markup can be used to send a GET request to the affected endpoint.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 3.3.1.");

  script_tag(name:"solution", value:"Update to version 3.3.1 (build 180214) or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/1e440208a8d8bfd71ad7802e6369a136e8bba3dd");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

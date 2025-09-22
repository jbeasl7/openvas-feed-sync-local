# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148429");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2022-07-12 08:04:26 +0000 (Tue, 12 Jul 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 13:22:00 +0000 (Tue, 22 Mar 2022)");

  script_cve_id("CVE-2022-26874");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Horde Groupware Webmail <= 5.2.22 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl");
  script_mandatory_keys("horde/detected");

  script_tag(name:"summary", value:"Horde Groupware Webmail is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The discovered vulnerability allows an authenticated user of a
  Horde instance to execute arbitrary code on the underlying server.

  The vulnerability can be exploited with a single GET request which can be triggered via
  cross-site request forgery. For this, an attacker can craft a malicious email and include an
  external image that when rendered exploits the vulnerability without further interaction of a
  victim. The only requirement is to have a victim open the malicious email.");

  # nb: 5.2.22 is the last stable release from 2017-09-21
  script_tag(name:"affected", value:"Horde Groupware Webmail version 5.2.22 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://blog.sonarsource.com/horde-webmail-rce-via-email/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "5.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

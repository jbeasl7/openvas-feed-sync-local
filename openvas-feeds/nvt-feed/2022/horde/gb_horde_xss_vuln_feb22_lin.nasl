# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147704");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2022-02-28 02:47:21 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 13:22:00 +0000 (Tue, 22 Mar 2022)");

  script_cve_id("CVE-2022-26874");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Horde Groupware Webmail <= 5.2.22 XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Horde Groupware Webmail is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can craft an OpenOffice document that when
  transformed to XHTML by Horde for preview can execute a malicious JavaScript payload. The
  vulnerability triggers when a targeted user views an attached OpenOffice document in the
  browser.");

  script_tag(name:"impact", value:"An attacker can steal all emails the victim has sent and
  received.");

  script_tag(name:"affected", value:"Horde MIME Viewer Library prior to version 2.2.4 as used in
  Horde Groupware Webmail version 5.2.22 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.

  If source code patching is an option the references include a link to a vendor patch which could
  be applied to the affected code.");

  script_xref(name:"URL", value:"https://blog.sonarsource.com/horde-webmail-account-takeover-via-email");
  script_xref(name:"URL", value:"https://github.com/horde/Mime_Viewer/commit/02b46cec1a7e8f1a6835b628850cd56b85963bb5");

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

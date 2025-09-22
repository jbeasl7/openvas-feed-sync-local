# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rocklobster:contact_form_7";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145080");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-12-22 03:26:35 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-22 12:57:00 +0000 (Tue, 22 Dec 2020)");

  script_cve_id("CVE-2020-35489");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Contact Form 7 Plugin < 5.3.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/contact-form-7/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Contact Form 7' is prone to an
  unrestricted file upload and remote code execution (RCE) vulnerability because a filename may
  contain special characters.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers may upload files of any type, bypassing all restrictions placed
  regarding the allowed upload-able file types on a website. Further, it allows an attacker to inject malicious
  content such as web shells.");

  script_tag(name:"affected", value:"WordPress Contact Form 7 plugin version 5.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 5.3.2 or later.");

  script_xref(name:"URL", value:"https://contactform7.com/2020/12/17/contact-form-7-532/");
  script_xref(name:"URL", value:"https://www.getastra.com/blog/911/plugin-exploit/contact-form-7-unrestricted-file-upload/");
  script_xref(name:"URL", value:"https://www.jinsonvarghese.com/unrestricted-file-upload-in-contact-form-7/");

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

if (version_is_less(version: version, test_version: "5.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

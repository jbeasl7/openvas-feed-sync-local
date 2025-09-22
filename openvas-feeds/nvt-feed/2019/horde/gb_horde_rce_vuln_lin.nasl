# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142487");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-06-04 09:08:15 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:13:00 +0000 (Mon, 18 Apr 2022)");

  script_cve_id("CVE-2019-9858");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Horde Groupware Webmail <= 5.2.22 RCE Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Horde Groupware Webmail is prone to an authenticated remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Horde/Form/Type.php contains a vulnerable class that handles
  image upload in forms. When the Horde_Form_Type_image method onSubmit() is called on uploads, it
  invokes the functions getImage() and _getUpload(), which uses unsanitized user input as a path to
  save the image. The unsanitized POST parameter object[photo][img][file] is saved in the
  $upload[img][file] PHP variable, allowing an attacker to manipulate the $tmp_file passed to
  move_uploaded_file() to save the uploaded file. By setting the parameter to (for example)
  ../usr/share/horde/static/bd.php, one can write a PHP backdoor inside the web root. The static/
  destination folder is a good candidate to drop the backdoor because it is always writable in
  Horde installations.");

  script_tag(name:"affected", value:"Horde Groupware Webmail version 5.2.22 and prior with Horde
  Form before version 2.0.19.");

  script_tag(name:"solution", value:"Update the Horde Form subcomponent to version 2.0.19 or
  later.");

  script_xref(name:"URL", value:"https://www.ratiosec.com/2019/horde-groupware-webmail-authenticated-arbitrary-file-injection-to-rce/");
  script_xref(name:"URL", value:"https://ssd-disclosure.com/ssd-advisory-horde-groupware-webmail-authenticated-arbitrary-file-injection-to-rce");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: version, test_version: "5.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

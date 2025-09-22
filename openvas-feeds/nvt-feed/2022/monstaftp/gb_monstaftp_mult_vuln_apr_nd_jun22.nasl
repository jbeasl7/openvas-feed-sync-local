# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:monsta:ftp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126041");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2022-06-15 12:15:33 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-05 18:28:00 +0000 (Thu, 05 May 2022)");

  script_cve_id("CVE-2022-27468", "CVE-2022-27469", "CVE-2022-31827");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MonstaFTP <= 2.10.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_monsta_ftp_detect.nasl");
  script_mandatory_keys("Monsta-FTP-master/Installed");

  script_tag(name:"summary", value:"MonstaFTP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-27468: An attacker can read and write arbitrary file upload which allows attackers to
  execute arbitrary code via a crafted file uploaded to the web server.

  - CVE-2020-27469: Allows an attacker to execute Server-Side Request Forgery (SSRF).

  - CVE-2020-31827: MonstaFTP was discovered to contain a Server-Side Request Forgery (SSRF) via the
  function performFetchRequest at HTTPFetcher.php.");

  script_tag(name:"affected", value:"MonstaFTP version 2.10.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://www.monstaftp.com/notes/");
  script_xref(name:"URL", value:"https://www.youtube.com/playlist?list=PLGCNgyyYX0yG9rF3Pd72H7qE9sfRA7d_i");
  script_xref(name:"URL", value:"https://github.com/zer0yu/CVE_Request/blob/master/MonstaFTP/MonstaFTP_v2_10_3_SSRF.md");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "2.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153081");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-12 04:23:51 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-37009", "CVE-2024-37010", "CVE-2024-37011", "CVE-2024-37012",
                "CVE-2024-42014");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.15.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-37009: URL manipulation when sharing files via email

  - CVE-2024-37010: Insecure direct object reference in external storage

  - CVE-2024-37011: Improper access control in SVG preview generation

  - CVE-2024-37012: Server-side request forgery (SSRF) in federated sharing API

  - CVE-2024-42014: Cross-site request forgery (CSRF) in diagnostics app");

  script_tag(name:"affected", value:"ownCloud prior to version 10.15.0.");

  script_tag(name:"solution", value:"Update to version 10.15.0 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/url-manipulation-when-sharing-files-via-email/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/insecure-direct-object-reference-in-external-storage/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/improper-access-control-in-svg-preview-generation/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/server-side-request-forgery-in-federated-sharing-api/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cross-site-request-forgery-in-diagnostics-app/");

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

if (version_is_less(version:version, test_version:"10.15.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"10.15.0", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

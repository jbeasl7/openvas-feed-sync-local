# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145673");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-03-29 08:48:10 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-24 18:40:00 +0000 (Wed, 24 Mar 2021)");

  script_cve_id("CVE-2021-25922");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR 4.2.0 < 6.0.0.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a reflected XSS vulnerability in OpenEMR at
  '/interface/orders/patient_match_dialog.php?key=1' endpoint in the 'key' query parameter. The
  'key' parameter is not sufficiently sanitized, allowing JavaScript to be inserted in the URL. The
  user-controlled parameter is sanitized using the addSlashes() method, but the attacker could
  bypass this by using the 'String.fromCharCode()' to make a more complex exploit.");

  script_tag(name:"affected", value:"OpenEMR version 4.2.0 through 6.0.0.");

  script_tag(name:"solution", value:"Update to version 6.0.0.1 or later.");

  script_xref(name:"URL", value:"https://www.whitesourcesoftware.com/vulnerability-database/CVE-2021-25922");

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

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "6.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

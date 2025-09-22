# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145671");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-03-29 08:36:57 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-24 18:19:00 +0000 (Wed, 24 Mar 2021)");

  script_cve_id("CVE-2021-25920");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR 2.7.2-rc1 < 6.0.0.1 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The OpenEMR application does not enforce adequate checks while
  creating users. Provided two users are named, one with uppercase and one with lowercase, it is
  possible for a malicious user to read and send sensitive messages on behalf of the victim user,
  while totally unknown to the victim user.");

  script_tag(name:"affected", value:"OpenEMR version 2.7.2-rc1 through 6.0.0.");

  script_tag(name:"solution", value:"Update to version 6.0.0.1 or later.");

  script_xref(name:"URL", value:"https://www.whitesourcesoftware.com/vulnerability-database/CVE-2021-25920");

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

if (version_in_range(version: version, test_version: "2.7.2", test_version2: "6.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

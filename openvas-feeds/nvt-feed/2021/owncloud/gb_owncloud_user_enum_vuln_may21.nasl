# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145995");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-05-21 04:42:54 +0000 (Fri, 21 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 00:04:00 +0000 (Wed, 26 May 2021)");

  script_cve_id("CVE-2021-29659");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.7 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The sharing dialog implements a user enumeration mitigation to
  prevent an authenticated user from getting a list of all accounts registered on the instance via
  the auto-complete dropdown. In the default configuration at least 3 characters of the name or
  email of the share-receiver ('Sharee') must match an existing account to trigger the autocomplete.

  Due to a bug in the related api endpoint the attacker can enumerate all users in a single request
  by entering three whitespaces.

  Secondary the retrieval of all users on a large instance could cause higher than average load
  on the instance.");

  script_tag(name:"affected", value:"ownCloud version 10.6 and probably prior.");

  script_tag(name:"solution", value:"Update to version 10.7 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-29659/");

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

if (version_is_less(version: version, test_version: "10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

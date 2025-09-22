# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freeipa:freeipa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140335");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-08-30 09:14:16 +0700 (Wed, 30 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-7030", "CVE-2016-9575");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreeIPA < Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freeipa_http_detect.nasl");
  script_mandatory_keys("freeipa/detected");

  script_tag(name:"summary", value:"FreeIPA is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-7030: DoS attack against kerberized services by abusing password policy

  - CVE-2016-9575: Insufficient permission check in certprofile-mod");

  script_tag(name:"affected", value:"FreeIPA prior to version 4.3.3.");

  script_tag(name:"solution", value:"Update to version 4.3.3 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/01/02/5");
  script_xref(name:"URL", value:"https://pagure.io/freeipa/issue/6561");
  script_xref(name:"URL", value:"https://pagure.io/freeipa/issue/6560");

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

if (version_is_less(version: version, test_version: "4.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

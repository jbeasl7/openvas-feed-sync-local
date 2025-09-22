# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:octopus:octopus_deploy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140601");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-14 11:07:09 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-17665");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Octopus Deploy Access Control Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_octopus_deploy_detect.nasl");
  script_mandatory_keys("octopus/octopus_deploy/detected");

  script_tag(name:"summary", value:"In Octopus Deploy, the machine update process doesn't check that the user
has access to all environments. This allows an access-control bypass because the set of environments to which a
machine is scoped may include environments in which the user lacks access.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Octopus Deploy versions prior to 4.1.3.");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_xref(name:"URL", value:"https://github.com/OctopusDeploy/Issues/issues/4073");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

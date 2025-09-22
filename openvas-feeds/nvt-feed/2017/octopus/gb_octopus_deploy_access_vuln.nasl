# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:octopus:octopus_deploy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140521");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-21 14:44:19 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-25 11:52:00 +0000 (Wed, 25 Oct 2017)");

  script_cve_id("CVE-2017-15610");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Octopus Deploy Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_octopus_deploy_detect.nasl");
  script_mandatory_keys("octopus/octopus_deploy/detected");

  script_tag(name:"summary", value:"An issue was discovered in Octopus. When the special Guest user account is
granted the CertificateExportPrivateKey permission, and Guest Access is enabled for the Octopus Server, an
attacker can sign in as the Guest account and export Certificates managed by Octopus, including the private key.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Octopus Deploy version 3.11.0 until 3.17.6.");

  script_tag(name:"solution", value:"Update to version 3.17.7 or later.");

  script_xref(name:"URL", value:"https://github.com/OctopusDeploy/Issues/issues/3869");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.11.0", test_version2: "3.17.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.17.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

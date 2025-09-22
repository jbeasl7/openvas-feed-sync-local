# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pkix_ssh_project:pkix_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114360");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-02-19 10:39:44 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 03:15:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-48795");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PKIX-SSH Prefix Truncation Attacks in SSH Specification (Terrapin Attack)");

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_pkixssh_ssh_detect.nasl");
  script_mandatory_keys("pkixssh/detected");

  script_tag(name:"summary", value:"PKIX-SSH is vulnerable to a novel prefix truncation attack
  (a.k.a. Terrapin attack).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Parts of the SSH specification are vulnerable to a novel prefix
  truncation attack (a.k.a. Terrapin attack), which allows a man-in-the-middle attacker to strip an
  arbitrary number of messages right after the initial key exchange, breaking SSH extension
  negotiation (RFC8308) in the process and thus downgrading connection security.");

  script_tag(name:"affected", value:"PKIX-SSH prior to version 14.4.");

  script_tag(name:"solution", value:"Update to version 14.4 or later.

  Notes:

  - Client and Server implementations need to run a fixed version to mitigate this flaw

  - Please create an override for this result if an adequate mitigation (e.g. in form of disabling
  the affected ciphers) has been applied and the risk is accepted that the mitigation won't be
  reverted again in the future");

  script_xref(name:"URL", value:"https://roumenpetrov.info/secsh/#news");
  script_xref(name:"URL", value:"https://terrapin-attack.com");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

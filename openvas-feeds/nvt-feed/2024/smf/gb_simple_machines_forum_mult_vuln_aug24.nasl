# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128045");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-08-05 16:00:20 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-24 14:27:53 +0000 (Mon, 24 Mar 2025)");

  script_cve_id("CVE-2024-7437", "CVE-2024-7438", "CVE-2025-2582", "CVE-2025-2583");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Simple Machines Forum (SMF) <= 2.1.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value: "The following flaws exist:

  - CVE-2024-7437: Affected is an unknown function of the component Delete User Handler. The
  manipulation of the argument aid leads to improper control of resource identifiers. It is possible
  to launch the attack remotely. The exploit has been disclosed to the public and may be used.

  - CVE-2004-7438: Affected by this vulnerability is an unknown functionality of the component User
  Alert Read Status Handler. The manipulation of the argument aid leads to improper control of
  resource identifiers. The attack can be launched remotely. The exploit has been disclosed to the
  public and may be used.

  - CVE-2025-2582: Affected by this issue is some unknown functionality of the file
  ManageAttachments.php. The manipulation of the argument Notice leads to cross site scripting. The
  attack may be launched remotely. The exploit has been disclosed to the public and may be used.

  - CVE-2025-2583: This affects an unknown part of the file ManageNews.php. The manipulation of the
  argument subject/message leads to cross site scripting. It is possible to initiate the attack
  remotely. The exploit has been disclosed to the public and may be used.");

  script_tag(name:"affected", value:"SMF versions 2.1.6 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Seems the vendor had acknowledge the vulnerabilities but haven't published any info on
  available fixes and sees the attack vector having a limited scope. Unless there is an official
  patch / reference from vendor side about available fixes this needs to be assumed unfixed.");

  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc1.md");
  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc2.md");
  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc3.md");
  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc4.md");
  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc5.md");
  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc6.md");
  script_xref(name:"URL", value:"https://www.simplemachines.org/community/index.php?topic=591344.0");

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

if (version_is_less_equal(version: version, test_version: "2.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

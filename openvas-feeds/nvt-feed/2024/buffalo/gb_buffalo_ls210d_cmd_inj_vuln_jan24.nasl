# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:buffalo:ls210d_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103099");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2024-05-17 15:01:24 +0000 (Fri, 17 May 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-06 16:35:06 +0000 (Tue, 06 Feb 2024)");

  script_cve_id("CVE-2023-49038");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Buffalo LS210D <= 1.84 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_buffalo_airstation_detect.nasl");
  script_mandatory_keys("buffalo/airstation/detected");

  script_tag(name:"summary", value:"Buffalo LS210D is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target
  host.");

  script_tag(name:"insight", value:"A command injection allows a remote authenticated attacker to
  inject arbitrary commands onto the NAS as root.");

  script_tag(name:"affected", value:"Buffalo LS210D firmware version 1.84 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: As a workaround implement the server-side filtering, that matches the filter used for the
  existing client-side JavaScript.");

  script_xref(name:"URL", value:"https://github.com/christopher-pace/CVE-2023-49038");
  script_xref(name:"URL", value:"https://dd00b71c8b1dfd11ad96-382cb7eb4238b9ee1c11c6780d1d2d1e.ssl.cf1.rackcdn.com/ls200-v184_win_en.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.84")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None (See solution for a workaround)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

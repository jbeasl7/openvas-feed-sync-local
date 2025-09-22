# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netatalk:netatalk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124622");
  script_version("2024-03-28T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-03-28 05:05:42 +0000 (Thu, 28 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-19 08:40:15 +0000 (Tue, 19 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-31 01:12:32 +0000 (Thu, 31 Mar 2022)");

  script_cve_id("CVE-2022-22995");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netatalk < 3.1.18 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_netatalk_asip_afp_detect.nasl");
  script_mandatory_keys("netatalk/detected");

  script_tag(name:"summary", value:"Netatalk is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The combination of primitives offered by SMB and AFP in their
  default configuration allows the arbitrary writing of files. By exploiting these combination of
  primitives, an attacker can execute arbitrary code.");

  script_tag(name:"affected", value:"Netatalk prior to version 3.1.18.");

  script_tag(name:"solution", value:"Update to version 3.1.18 or later.");

  script_xref(name:"URL", value:"https://netatalk.io/3.1/ReleaseNotes3.1.18");
  script_xref(name:"URL", value:"https://github.com/Netatalk/netatalk/issues/480");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.18");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

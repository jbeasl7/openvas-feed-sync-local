# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:schneider_electric:homelynk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106746");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-12 14:05:46 +0200 (Wed, 12 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-02 02:13:00 +0000 (Wed, 02 Feb 2022)");

  script_cve_id("CVE-2017-7689");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Schneider Electric homeLYnk Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_schneider_homelynk_controller_detect.nasl");
  script_mandatory_keys("schneider_homelynk/detected");

  script_tag(name:"summary", value:"Schneider Electric homeLYnk Controller is prone to a command injection
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The homeLYnk controller is susceptible to a command injection attack.");

  script_tag(name:"affected", value:"Schneider Electric homeLYnk Controller prior to version 1.5.0.");

  script_tag(name:"solution", value:"Update the firmware to version 1.5.0 or later.");

  script_xref(name:"URL", value:"http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2017-052-02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:hp:integrated_lights-out_4_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140325");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-25 09:17:16 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-23 13:05:00 +0000 (Mon, 23 Jul 2018)");

  script_cve_id("CVE-2017-12542");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Integrated Lights-Out (iLO) 4 Multiple Remote Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("hp/ilo/detected");

  script_tag(name:"summary", value:"HP Integrated Lights-Out (iLO) 4 is prone to multiple remote vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A potential security vulnerability has been identified in HPE Integrated
  Lights-out (iLO 4). The vulnerability could be exploited remotely to allow authentication bypass and execution of
  code.");

  script_tag(name:"affected", value:"HPE Integrated Lights-Out 4 (iLO 4) prior to v2.53.");

  script_tag(name:"solution", value:"HPE has provided firmware updates to resolve this vulnerability. iLO 4
  version v2.53 or newer.");

  script_xref(name:"URL", value:"http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=hpesbhf03769en_us");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.53");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

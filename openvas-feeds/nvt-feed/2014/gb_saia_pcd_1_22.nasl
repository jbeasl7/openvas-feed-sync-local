# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/h:saia_burgess_controls";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103895");
  script_version("2025-04-22T10:32:18+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Saia PCD < 1.22 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://sbc-support.com/en/product-index/firmware-for-saia-pcdr-cosinus/general-information/");
  script_xref(name:"URL", value:"https://www.heise.de/news/Kritische-Schwachstelle-in-hunderten-Industrieanlagen-1854385.html");
  script_xref(name:"URL", value:"https://www.heise.de/news/Verwundbare-Industrieanlagen-Fernsteuerbares-Gotteshaus-1902245.html");

  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-01-28 11:22:01 +0100 (Tue, 28 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_saia_pcd_web_detect.nasl");
  script_mandatory_keys("saia_pcd/detected", "saia_pcd/version");

  script_tag(name:"summary", value:"Saia PCD is prone to a vulnerability in the user
  authentication.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_tag(name:"insight", value:"The firmware of the remote Saia PCD is older then 1.22.x");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data.");

  script_tag(name:"affected", value:"Saia PCD with firmware versions prior to 1.22.x.");

  script_tag(name:"solution", value:"Update the firmware to version 1.22.x or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.22");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

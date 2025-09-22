# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:western_digital:wdtv_live_hub";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141284");
  script_version("2025-01-20T11:07:33+0000");
  script_tag(name:"last_modification", value:"2025-01-20 11:07:33 +0000 (Mon, 20 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-07-09 14:38:27 +0200 (Mon, 09 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-28 14:13:00 +0000 (Tue, 28 May 2019)");

  script_cve_id("CVE-2018-1151");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Western Digital WD TV Live Hub RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wd_wdtv_detect.nasl");
  script_mandatory_keys("wd_wdtv/detected");

  script_tag(name:"summary", value:"The web server on Western Digital TV Live Hub 3.12.13 allow unauthenticated
remote attackers to execute arbitrary code or cause denial of service via crafted HTTP requests to
toServerValue.cgi.");

  script_tag(name:"affected", value:"Western Digital TV Live Hub 3.12.13 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2018-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.12.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ftpdmin:ftpdmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113690");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2020-05-18 12:23:23 +0000 (Mon, 18 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-22 19:39:00 +0000 (Wed, 22 Apr 2020)");

  script_cve_id("CVE-2020-10813", "CVE-2024-0261");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("FTPDMIN <= 0.96 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("ftpdmin_detect.nasl");
  script_mandatory_keys("ftpdmin/installed");

  script_tag(name:"summary", value:"FTPDMIN is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable via a crafted packet.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the
  application.");

  script_tag(name:"affected", value:"FTPDMIN through version 0.96.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.povonsec.com/ftpdmin-denial-of-service-exploit/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/176342/FTPDMIN-0.96-Denial-Of-Service.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "0.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

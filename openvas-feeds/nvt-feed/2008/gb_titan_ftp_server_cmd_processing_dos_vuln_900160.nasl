# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:southrivertech:titan_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900160");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-23 14:16:10 +0200 (Thu, 23 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2008-6082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Titan FTP Server < 6.26.631 Remote DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_southrivertech_titan_ftp_server_consolidation.nasl");
  script_mandatory_keys("titan_ftp_server/detected");

  script_tag(name:"summary", value:"Titan FTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in the 'SITE WHO' command processing,
  which can be exploited to exhaust available CPU resources.");

  script_tag(name:"impact", value:"Successful exploitation will cause a denial of service.");

  script_tag(name:"affected", value:"Titan FTP Server prior to version 6.26.631.");

  script_tag(name:"solution", value:"Update to version 6.26.631 or later.");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31757");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32269/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

if (version_is_less(version: version, test_version: "6.26.631")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.26.631");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142662");
  script_version("2024-11-29T15:40:53+0000");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-07-24 03:20:49 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 16:39:00 +0000 (Wed, 01 Mar 2023)");

  script_cve_id("CVE-2019-12815");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ProFTPD <= 1.3.6 'mod_copy' Arbitrary File Copy Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_tag(name:"summary", value:"ProFTPD is prone to an arbitrary file copy vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An arbitrary file copy vulnerability in mod_copy in ProFTPD
  allows for remote code execution (RCE) and information disclosure without authentication, a
  related issue to CVE-2015-3306.");

  script_tag(name:"affected", value:"ProFTPD version 1.3.6 and prior.");

  script_tag(name:"solution", value:"As a workaround disable mod_copy in the ProFTPD configuration
  file.");

  script_xref(name:"URL", value:"https://tbspace.de/cve201912815proftpd.html");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=4372");
  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/proftpd-vulnerability-lets-users-copy-files-without-permission/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

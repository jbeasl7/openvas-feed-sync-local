# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:coppermine:coppermine_photo_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141958");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-02-05 11:17:46 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 19:16:00 +0000 (Tue, 07 May 2019)");

  script_cve_id("CVE-2018-14478");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Coppermine < 1.5.48 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("coppermine_detect.nasl");
  script_mandatory_keys("coppermine_gallery/installed");

  script_tag(name:"summary", value:"Coppermine is prone to multiple reflected cross-site scripting
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Coppermine prior to version 1.5.48.");

  script_tag(name:"solution", value:"Update to version 1.5.48 or later.");

  script_xref(name:"URL", value:"https://www.netsparker.com/web-applications-advisories/ns-18-050-cross-site-scripting-in-coppermine/");
  script_xref(name:"URL", value:"http://forum.coppermine-gallery.net/index.php/topic,79577.0.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.5.48")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.48");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

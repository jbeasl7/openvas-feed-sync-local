# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141186");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-15 11:22:07 +0700 (Fri, 15 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-5347");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Seagate Personal Cloud < 4.3.18.0 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_nas_detect.nasl");
  script_mandatory_keys("seagate_nas/detected");

  script_tag(name:"summary", value:"Seagate Media Server in Seagate Personal Cloud has unauthenticated command
  injection in the uploadTelemetry and getLogs functions in views.py because .psp URLs are handled by the
  fastcgi.server component and shell metacharacters are mishandled.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary commands.");

  script_tag(name:"solution", value:"Update to firmware version 4.3.18.0 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3548");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/h:seagate:personal_cloud", "cpe:/h:seagate:personal_cloud_2_bay");
if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.18.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.18.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

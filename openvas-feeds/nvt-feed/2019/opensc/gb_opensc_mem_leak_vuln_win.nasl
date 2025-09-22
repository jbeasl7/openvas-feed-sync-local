# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112499");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-01-24 15:36:12 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-6502");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSC < 0.20.0 Memory Leak Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opensc_detect_win.nasl");
  script_mandatory_keys("opensc/win/detected");

  script_tag(name:"summary", value:"OpenSC is prone to a memory leak vulnerability.");
  script_tag(name:"insight", value:"sc_context_create in ctx.c in libopensc in OpenSC has a memory leak, via a call from eidenv.c.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"OpenSC prior to version 0.20.0.");
  script_tag(name:"solution", value:"Update to OpenSC version 0.20.0 or later.");

  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/issues/1586");

  exit(0);
}

CPE = "cpe:/a:opensc-project:opensc";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version: vers, test_version: "0.20.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.20.0", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

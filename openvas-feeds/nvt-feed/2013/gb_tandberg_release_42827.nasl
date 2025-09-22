# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tandberg:codec";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103788");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-09-12 13:33:18 +0200 (Thu, 12 Sep 2013)");
  script_cve_id("CVE-2009-3947");
  script_name("Tandberg MXP Series Video Conferencing Device <= F8.2 Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_tandberg_devices_detect.nasl");
  script_mandatory_keys("tandberg/device/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127181704/http://www.securityfocus.com/bid/42827");
  script_xref(name:"URL", value:"ftp://ftp.tandberg.com/pub/software/endpoints/mxp/TANDBERG%20MXP%20Endpoints%20Software%20Release%20Notes%20%28F9%29.pdf");

  script_tag(name:"summary", value:"Tandberg MXP Series devices are prone to a remote denial of
  service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable codec release version is present on the
  target host.");

  script_tag(name:"insight", value:"The devices are exposed to a remote DoS issue because they fail
  to properly validate user-supplied data.");

  script_tag(name:"impact", value:"A successful exploit will cause the device to crash, denying
  service to legitimate users.");

  script_tag(name:"affected", value:"Tandberg MXP Series devices with codec release version F8.2 are
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to version F9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

rep_version = toupper(version);
version = eregmatch(pattern:"f([0-9.]+)", string:version);
if(isnull(version[1]))
  exit(0);

if(version_is_less_equal(version:version[1], test_version:"8.2")) {
  report = report_fixed_ver(installed_version:rep_version, fixed_version:"F9.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

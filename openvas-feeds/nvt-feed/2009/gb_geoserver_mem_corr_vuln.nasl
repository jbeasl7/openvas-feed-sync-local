# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:geoserver:geoserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900946");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2008-7227");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GeoServer < 1.6.1, 1.7.x < 1.7.0-beta1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_geoserver_http_detect.nasl");
  script_mandatory_keys("geoserver/detected");

  script_tag(name:"summary", value:"GeoServer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists when PartialBufferOutputStream2 flushes the
  buffer contents even when it is handling an 'in memory buffer', which prevents the reporting of a
  service exception, with unknown impact and attack vectors.");

  script_tag(name:"impact", value:"Successful attacks may lead to failure to report service
  exception if the code encoding the output calls flush() before having written the full contents
  to the output.");

  script_tag(name:"affected", value:"GeoServer prior to version 1.6.1 and 1.7.0-beta1.");

  script_tag(name:"solution", value:"Update to version 1.6.1, 1.7.0-beta1 or later.");

  script_xref(name:"URL", value:"http://jira.codehaus.org/browse/GEOS-1747");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version:"1.6.1") ||
    version_in_range_exclusive(version: version, test_version_lo:"1.7.0.beta", test_version_up: "1.7.0.beta1")){
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.1 / 1.7.0.beta1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

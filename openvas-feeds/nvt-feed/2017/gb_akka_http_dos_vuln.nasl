# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:akka:http";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140486");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-03 16:48:17 +0700 (Fri, 03 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-13 18:07:00 +0000 (Fri, 13 Oct 2017)");

  script_cve_id("CVE-2017-1000118");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("akka HTTP DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_akka_http_detect.nasl");
  script_mandatory_keys("akka_http/installed");

  script_tag(name:"summary", value:"akka HTTP is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"Handling a request that carries an Accept header with an unsupported media
range starting with a wildcard but having a specific subtype (e.g. */boom) leads to a stack overflow during
negotiation of the content type. Per default, stack overflows are treated as fatal errors, so that the JVM
process will shut itself down immediately.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 10.0.6 or later.");

  script_xref(name:"URL", value:"https://doc.akka.io/docs/akka-http/10.0.6/security/2017-05-03-illegal-media-range-in-accept-header-causes-stackoverflowerror.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

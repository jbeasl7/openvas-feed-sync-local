# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:java_system_application_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100715");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:N");
  script_cve_id("CVE-2010-2397");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sun Java System Application Server Local Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41638");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpujul2010.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("secpod_sun_java_app_serv_detect.nasl");
  script_mandatory_keys("sun_java_appserver/installed");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
information.");

  script_tag(name:"summary", value:"Sun Java System Application Server is prone to a local vulnerability.

The 'GUI' sub component is affected.

This vulnerability affects the following supported versions: Sun Java System Application Server 8.0, 8.1, 8.2.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8",test_version2: "8.2")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"8 - 8.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

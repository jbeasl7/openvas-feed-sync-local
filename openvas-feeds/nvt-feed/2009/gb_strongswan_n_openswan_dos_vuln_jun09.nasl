# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900386");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-2185");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan/Openswan DoS Vulnerability (Jun 2009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openswan_ssh_login_detect.nasl", "gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("openswan_or_strongswan/detected");

  script_tag(name:"summary", value:"strongSwan / Openswan is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Error in 'ASN.1' parser in pluto/asn1.c, libstrongswan/asn1/asn1.c,
  and libstrongswan/asn1/asn1_parser.c is caused via an 'X.509' certificate with crafted Relative
  Distinguished Names (RDNs), a crafted UTCTIME string, or a crafted GENERALIZEDTIME string.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause pluto IKE
  daemon crash.");

  script_tag(name:"affected", value:"- Openswan: version 2.6 before 2.6.22 and 2.4 before 2.4.15

  - strongSwan: version 2.8 before 2.8.10, 4.2 before 4.2.16, and 4.3 before 4.3.2");

  script_tag(name:"solution", value:"- Openswan: Update to version 2.6.22, 2.4.15 or later

  - strongSwan: Update to version 2.8.10, 4.2.16, 4.3.2 or later");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35522");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1639");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:strongswan:strongswan", "cpe:/a:openswan:openswan");

if (!infos = get_app_version_and_location_from_list(cpe_list: cpe_list, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
cpe = infos["cpe"];

if ("cpe:/a:openswan:openswan" >< cpe) {
  if (version_in_range(version: version, test_version: "2.4", test_version2: "2.4.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.15", install_path: location);
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "2.6", test_version2: "2.6.21")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.6.22", install_path: location);
    security_message(port: 0, data: report);
    exit(0);
  }

} else {
  if (version_in_range(version: version, test_version: "2.8.0", test_version2: "2.8.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.8.10", install_path: location);
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.15")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.16", install_path: location);
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2", install_path: location);
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
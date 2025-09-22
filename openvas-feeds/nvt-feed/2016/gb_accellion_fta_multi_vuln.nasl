# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:accellion:secure_file_transfer_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106074");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-05-13 11:42:35 +0700 (Fri, 13 May 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-10 15:20:00 +0000 (Tue, 10 May 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-2350", "CVE-2016-2351", "CVE-2016-2352", "CVE-2016-2353");

  script_name("Accellion FTA Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_accellion_fta_detect.nasl");
  script_mandatory_keys("accellion_fta/installed");

  script_tag(name:"summary", value:"Accellion FTA is prone to multiple vulnerabilities");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Accellion File Transfer Appliance:

  - Multiple cross-site scripting (XSS) vulnerabilities in getimageajax.php, move_partition_frame.html and
wmInfo.html (CVE-2016-2350).

  - SQL injection vulnerability in home/seos/courier/security_key2.api via the client_id parameter (CVE-2016-2351).

  - Execution of arbitrary commands by leveraging the YUM_CLIENT restricted-user role (CVE-2016-2352).

  - Allowing local users to add an SSH key to an arbitrary group (CVE-2016-2353).");

  script_tag(name:"impact", value:"Remote unauthenticated attackers may inject arbitrary web scripts or
execute arbitrary SQL commands. Remote authenticated attackers may execute arbitrary commands and local users
gain privileges.");

  script_tag(name:"affected", value:"Accellion FTA Version 9_11_210 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 9_12_40 or later");

  script_xref(name:"URL", value:"http://devco.re/blog/2016/04/21/how-I-hacked-facebook-and-found-someones-backdoor-script-eng-ver/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.12.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.12.40");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

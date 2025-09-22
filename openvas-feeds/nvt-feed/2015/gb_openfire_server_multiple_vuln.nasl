# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806061");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-19 15:36:42 +0530 (Mon, 19 Oct 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-6972", "CVE-2015-6973", "CVE-2015-7707");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("OpenFire <= 3.10.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_http_detect.nasl");
  script_mandatory_keys("openfire/detected");

  script_tag(name:"summary", value:"OpenFire Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Insufficient validation of input passed via the 'hostname' parameter to
  server-session-details.jsp script, 'search' parameter to group-summary.jsp script,
  'Group Chat Name' and 'URL Name' fields in create-bookmark.jsp script.

  - CSRF token does not exists when making some POST and Get requests.

  - plugin-admin.jsp script does not restrict plugin files upload.

  - Insufficient validation for plugin downloads by available-plugins.jsp script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site and
  upload and download of arbitrary files, and to take malicious actions against the application.");

  script_tag(name:"affected", value:"Openfire Server version 3.10.2 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38188");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38189");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38191");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38192");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

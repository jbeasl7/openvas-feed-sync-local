# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801888");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-1209");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server WS-Security XML Encryption Weakness Vulnerability (May 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by a weak encryption algorithm being used by
  WS-Security to encrypt data exchanged via a Web Service (JAX-WS or JAX-RPC), which could allow
  attackers to decrypt the encrypted data contained in web requests.");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to obtain
  plaintext data from a JAX-RPC or JAX-WS Web Services.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.39 and 7.x prior to 7.0.0.17.");

  script_tag(name:"solution", value:"Update to version 6.1.0.39, 7.0.0.17 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67115");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47831");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1084");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24029632");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21474220");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.39");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.17");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

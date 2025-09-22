# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:secureideas:base";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100323");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_cve_id("CVE-2009-4590", "CVE-2009-4591", "CVE-2009-4592", "CVE-2009-4837", "CVE-2009-4838", "CVE-2009-4839");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Basic Analysis and Security Engine Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18298");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("base_detect.nasl");
  script_mandatory_keys("BASE/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Basic Analysis and Security Engine (BASE) is prone to multiple
  input-validation vulnerabilities because it fails to adequately sanitize user-supplied input. These
  vulnerabilities include an SQL-injection issue, a cross-site scripting issue, and a local file-include issue.");

  script_tag(name:"impact", value:"Exploiting these issues can allow an attacker to steal cookie-based authentication
  credentials, view and execute local files within the context of the webserver, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"These issues affect versions prior to BASE 1.4.4.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:etcd:etcd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141874");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-01-15 10:13:42 +0700 (Tue, 15 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-24 12:24:00 +0000 (Thu, 24 Oct 2019)");

  script_cve_id("CVE-2018-16886");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("etcd 3.2.x, 3.3.x Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_http_detect.nasl");
  script_mandatory_keys("etcd/detected");

  script_tag(name:"summary", value:"etcd is vulnerable to an improper authentication issue when
  role-based access control (RBAC) is used and client-cert-auth is enabled.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an etcd client server TLS certificate contains a Common Name
  (CN) which matches a valid RBAC username, a remote attacker may authenticate as that user with
  any valid (trusted) client certificate in a REST API request to the gRPC-gateway.");

  script_tag(name:"affected", value:"etcd version 3.2.x and 3.3.x.");

  script_tag(name:"solution", value:"Update to version 3.2.26, 3.3.11 or later.");

  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/pull/10366");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/blob/1eee465a43720d713bb69f7b7f5e120135fdb1ac/CHANGELOG-3.2.md#security-authentication");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/blob/1eee465a43720d713bb69f7b7f5e120135fdb1ac/CHANGELOG-3.3.md#security-authentication");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.2", test_version2: "3.2.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.3", test_version2: "3.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112477");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-04 10:22:22 +0100 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-18264");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kubernetes Dashboard < 1.10.1 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kubernetes_dashboard_detect.nasl");
  script_mandatory_keys("kubernetes/dashboard/detected");

  script_tag(name:"summary", value:"Kubernetes Dashboard is prone to an authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This vulnerability allows users the ability to bypass authentication
  and gain access to the Dashboard as a service account with the ability to read secrets within the cluster.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Kubernetes Dashboard before version 1.10.1.");

  script_tag(name:"solution", value:"Update to version 1.10.1 or later.");

  script_xref(name:"URL", value:"https://groups.google.com/forum/#!topic/kubernetes-announce/yBrFf5nmvfI");
  script_xref(name:"URL", value:"https://github.com/kubernetes/dashboard/releases/tag/v1.10.1");
  script_xref(name:"URL", value:"https://github.com/kubernetes/dashboard/pull/3400");
  script_xref(name:"URL", value:"https://github.com/kubernetes/dashboard/pull/3289");

  exit(0);
}

CPE = "cpe:/a:kubernetes:dashboard";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

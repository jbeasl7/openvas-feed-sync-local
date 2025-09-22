# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:commons_ognl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118713");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-21 13:13:37 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2025-53192");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Apache Commons OGNL Security Bypass Vulnerability (Aug 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_commons_consolidation.nasl");
  script_mandatory_keys("apache/commons/detected");

  script_tag(name:"summary", value:"The Apache Commons OGNL library is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When using the API 'Ognl.getValue', the OGNL engine parses
  and evaluates the provided expression with powerful capabilities, including accessing and
  invoking related methods, etc. Although 'OgnlRuntime' attempts to restrict certain dangerous
  classes and methods (such as java.lang.Runtime) through a blocklist, these restrictions are not
  comprehensive.");

  script_tag(name:"impact", value:"Attackers may be able to bypass the restrictions by leveraging
  class objects that are not covered by the blocklist and potentially achieve arbitrary code
  execution.");

  script_tag(name:"affected", value:"All versions of Apache Commons OGNL.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Vendor Notes:

  - As this project is retired, we do not plan to release a version that fixes this issue. Users
  are recommended to find an alternative or restrict access to the instance to trusted users.

  - This vulnerability only affects products that are no longer supported by the maintainer.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/2gj8tjl6vz949nnp3yxz3okm9xz2k7sp");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
security_message(port: port, data: report);

exit(0);

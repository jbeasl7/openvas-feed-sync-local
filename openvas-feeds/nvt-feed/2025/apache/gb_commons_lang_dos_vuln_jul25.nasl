# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154930");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-15 02:12:31 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2025-48924");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Commons Lang DoS Vulnerability (Jul 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_commons_consolidation.nasl");
  script_mandatory_keys("apache/commons/detected");

  script_tag(name:"summary", value:"The Apache Commons Lang library is prone to a denial
  of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The methods ClassUtils.getClass(...) can throw
  StackOverflowError on very long inputs. Because an Error is usually not handled by applications
  and libraries, a StackOverflowError could cause an application to stop.");

  script_tag(name:"affected", value:"Apache Commons Lang version 2.0 through 2.6 and 3.0 prior to
  3.18.0.");

  script_tag(name:"solution", value:"Update to version 3.18.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/bgv0lpswokgol11tloxnjfzdl7yrc1g1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:apache:commons_lang",
                     "cpe:/a:apache:commons_lang2",
                     "cpe:/a:apache:commons_lang3");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!infos = get_app_version_and_location(cpe: cpe, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.18.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.18.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

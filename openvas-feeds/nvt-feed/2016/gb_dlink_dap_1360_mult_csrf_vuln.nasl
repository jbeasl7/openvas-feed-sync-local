# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dap-1360_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810235");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-12-10 10:43:14 +0530 (Sat, 10 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-10027");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DAP-1360 < 2.5.4 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1360 devices are prone to multiple cross-site request
  forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple cross-site request forgery
  errors in Wi-Fi - WPS method.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to hijack the
  authentication of unspecified users for requests that change the MAC filter restrict mode, add a
  MAC address to the filter, or remove a MAC address from the filter via a crafted request to
  index.cgi.");

  script_tag(name:"affected", value:"D-Link DAP-1360 prior to version 2.5.4.");

  script_tag(name:"solution", value:"Update to firmware version 2.5.4 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Dec/9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"2.5.4")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.5.4");
  security_message(port:port, data:report);
}

exit(99);

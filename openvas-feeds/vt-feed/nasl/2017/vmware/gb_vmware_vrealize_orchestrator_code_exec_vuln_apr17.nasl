# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vrealize_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811005");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2017-04-20 18:03:53 +0530 (Thu, 20 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:40:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2015-6934");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Patch for 4.2.x / 5.x not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Orchestrator RCE Vulnerability (VMSA-2015-0009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_orchestrator_http_detect.nasl");
  script_mandatory_keys("vmware/vrealize/orchestrator/detected");

  script_tag(name:"summary", value:"VMware vRealize Orchestrator is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a deserialization error involving Apache
  Commons-collections and a specially constructed chain of classes exists.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"VMware vRealize Orchestrator 4.2.x, 5.x, and 6.x before 6.0.5.");

  script_tag(name:"solution", value:"Update to version 6.0.5 or apply the patch provided by the
  vendor in the referenced advisory.");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2015-0009.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version =~ "^4\.2\." || version =~ "^5\." ||
    version_in_range(version:version, test_version:"6.0", test_version2:"6.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.0.5 / apply the patch provided by the vendor");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
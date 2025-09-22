# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107212");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2017-05-31 19:18:23 +0200 (Wed, 31 May 2017)");
  script_cve_id("CVE-2017-5572");

  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix XenServer CVE-2017-5572 Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Citrix XenServer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause denial-of-service condition.");

  script_tag(name:"affected", value:"Citrix XenServer 6.0.2, Citrix XenServer 7.0, Citrix XenServer 6.5 SP1,
  Citrix XenServer 6.5, Citrix XenServer 6.2.0 Sp1, Citrix XenServer 6.2.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95801");
  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220112");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_xenserver_web_detect.nasl");
  script_mandatory_keys("citrix_xenserver/webgui/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_equal(version:ver, test_version:"6.0.2") ||
    version_is_equal(version:ver, test_version:"6.5.2") ||
    version_is_equal(version:ver, test_version:"6.2") ||
    version_is_equal(version:ver, test_version:"7.0")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"Apply the specific hotfix supplied by the vendor.");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

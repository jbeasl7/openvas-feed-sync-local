# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107831");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2018-0739");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: OpenSSL Vulnerability in Some Huawei Products (huawei-sa-20180613-01-openssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Constructed ASN.1 types with a recursive definition in some
  OpenSSL versions could eventually exceed the stack given malicious input with excessive
  recursion.");

  script_tag(name:"insight", value:"Constructed ASN.1 types with a recursive definition in some
  OpenSSL versions could eventually exceed the stack given malicious input with excessive
  recursion. Successful exploit could result in a Denial Of Service attack. (Vulnerability ID:
  HWPSIRT-2018-03073)This vulnerability has been assigned a Common Vulnerabilities and Exposures
  (CVE) ID: CVE-2018-0739. Huawei has released software updates to fix this vulnerability. This
  advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could result in a Denial Of Service attack.");

  # nb: The advisory also contains a huge amount of (probably non-VRP) products which are currently
  # not supported and not included here like e.g.:
  # - DP300 (videoconferencing desktop endpoint.)
  # - UPS2000 (UPS device)
  # - AnyOffice
  #
  # Furthermore e.g. EulerOS with an affected version V200R005C00SPC200 is included for unknown
  # reasons. This product doesn't have such versions and is a Linux distro with dedicated package
  # versions.
  #
  # The only known VRP / Roter device is AR3200 which has been included here.
  script_tag(name:"affected", value:"AR3200 versions V200R008C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180613-01-openssl-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar3200_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

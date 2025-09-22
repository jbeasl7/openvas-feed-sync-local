# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153699");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-02 07:08:12 +0000 (Thu, 02 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-10 20:32:19 +0000 (Fri, 10 Jan 2025)");

  script_cve_id("CVE-2020-1818", "CVE-2020-1819", "CVE-2020-1820", "CVE-2020-1821",
                "CVE-2020-1822", "CVE-2020-1823", "CVE-2020-1824");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple OOB Read Vulnerabilities in COPS implementation of Some Huawei Products (huawei-sa-20191218-01-cops)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There are multiple out of bounds (OOB) read vulnerabilities in
  the implementation of the Common Open Policy Service (COPS) protocol of some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific decoding function may occur out-of-bounds read
  when processes an incoming data packet.");

  script_tag(name:"impact", value:"Successful exploit of these vulnerabilities may disrupt service
  on the affected device.");

  script_tag(name:"affected", value:"IPS Module versions V500R001C30 V500R001C60 V500R005C00

  NGFW Module versions V500R002C00 V500R002C20 V500R005C00

  NIP6300 versions V500R001C30 V500R001C60 V500R005C00

  NIP6600 versions V500R001C30 V500R001C60 V500R005C00

  NIP6800 versions V500R001C60 V500R005C00

  Secospace USG6300 versions V500R001C30 V500R001C60 V500R005C00

  Secospace USG6500 versions V500R001C30 V500R001C60 V500R005C00

  Secospace USG6600 versions V500R001C30 V500R005C00

  USG6000V versions V500R003C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/2020/huawei-sa-20191218-01-cops-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg6000v_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:usg6[35]") {
  if (version =~ "^V500R001C30" || version =~ "^V500R001C60" || version =~ "^V500R005C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C20SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:usg66") {
  if (version =~ "^V500R001C30" || version =~ "^V500R005C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C20SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "cpe:/o:huawei:usg6000v") {
  if (version =~ "^V500R003C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C00SPC100");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

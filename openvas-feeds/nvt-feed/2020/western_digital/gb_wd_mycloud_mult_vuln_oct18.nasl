# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108926");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-09-02 11:07:07 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-23 14:27:29 +0000 (Mon, 23 Apr 2018)");

  script_cve_id("CVE-2016-10108", "CVE-2016-10107", "CVE-2016-5195", "CVE-2012-5958",
                "CVE-2010-5312", "CVE-2018-1301", "CVE-2018-1302", "CVE-2018-1303",
                "CVE-2018-1312", "CVE-2017-15715", "CVE-2015-6834", "CVE-2015-6835",
                "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838", "CVE-2014-9767",
                "CVE-2018-5764");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products < 2.12.127 / 2.20 - 2.30 < 2.31.149 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-19002-my-cloud-firmware-2-12-127");
  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-mirror-firmware-release-2-12-127-01-08-2019/200839");
  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-ex2-firmware-release-2-12-127-01-8-19/219790");
  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-firmware-versions-2-31-149-10-19-18/229690");
  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-firmware-versions-2-31-149-10-19-18/229696");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following issues have been addressed:

  - Resolved multiple command injection vulnerabilities including CVE-2016-10108 and CVE-2016-10107

  - Resolved multiple cross site request forgery (CSRF) vulnerabilities

  - Resolved a Linux kernel Dirty Cow vulnerability (CVE-2016-5195)

  - Resolved multiple denial-of-service vulnerabilities

  - Improved security by disabling SSH shadow information

  - Resolved a buffer overflow issue that could lead to unauthenticated access

  - Resolved a click-jacking vulnerability in the webinterface

  - Resolved multiple security issues in the Webfile viewer on-devic eapp

  - Improved the security of volume mount options

  - Resolved multiple security issues in the EULA onboarding flow

  - Resolved leakage of debug messages in the webinterface

  - Improved credential handling for the remote MyCloud-to-MyCloud backup feature

  - Improved credential handling for upload-logs-to-support option

  Additionally the following components received an update containing security fixes:

  - Apache v2.4.34 (CVE-2018-1301, CVE-2018-1302, CVE-2018-1303, CVE-2018-1312, CVE-2017-15715)

  - PHP v5.4.45 (CVE-2015-6834, CVE-2015-6835, CVE-2015-6836, CVE-2015-6837, CVE-2015-6838,
  CVE-2014-9767)

  - OpenSSH v7.5p1

  - OpenSSL v1.0.1u

  - libupnp v1.6.25 (CVE-2012-5958)

  - jQuery v3.3.1 (CVE-2010-5312)

  - Rsync v3.1.3 (CVE-2018-5764)");

  script_tag(name:"affected", value:"Western Digital My Cloud with firmware versions prior to
  2.12.127 and 2.2 - 2.3 versions prior to 2.31.149.");

  script_tag(name:"solution", value:"Update to firmware version 2.12.127, 2.31.149 or later.

  Note: Some My Cloud products are already end-of-life and doesn't receive any updates anymore.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2_firmware",
                     "cpe:/o:wdc:my_cloud_ex4_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "2.12.127")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.127");
  security_message(port: 0, data: report);
  exit(0);
}

else if (version =~ "^2\.[23][0-9]\." && version_is_less(version: version, test_version: "2.31.149")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.31.149");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

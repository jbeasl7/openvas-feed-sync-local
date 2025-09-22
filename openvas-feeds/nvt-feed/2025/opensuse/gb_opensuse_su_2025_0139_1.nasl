# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0139.1");
  script_cve_id("CVE-2024-11403", "CVE-2024-11498");
  script_tag(name:"creation_date", value:"2025-05-02 04:06:46 +0000 (Fri, 02 May 2025)");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-23 19:48:17 +0000 (Wed, 23 Jul 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0139-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MF2M2SVCJLFCMVUJBZPKNUD26RAA7I4W/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233785");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjxl' package(s) announced via the openSUSE-SU-2025:0139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libjxl fixes the following issues:

- Update to release 0.8.4
 * Huffman lookup table size fix [CVE-2024-11403]
 * Check height limit in modular trees [CVE-2024-11498]");

  script_tag(name:"affected", value:"'libjxl' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-jxl", rpm:"gdk-pixbuf-loader-jxl~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-jxl", rpm:"gimp-plugin-jxl~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jxl-thumbnailer", rpm:"jxl-thumbnailer~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjxl-devel", rpm:"libjxl-devel~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjxl-tools", rpm:"libjxl-tools~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjxl0_8", rpm:"libjxl0_8~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjxl0_8-32bit", rpm:"libjxl0_8-32bit~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjxl0_8-64bit", rpm:"libjxl0_8-64bit~0.8.4~bp156.3.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

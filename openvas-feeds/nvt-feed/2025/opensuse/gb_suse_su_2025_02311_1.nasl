# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02311.1");
  script_cve_id("CVE-2025-4565");
  script_tag(name:"creation_date", value:"2025-07-17 04:17:49 +0000 (Thu, 17 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-14 17:05:37 +0000 (Thu, 14 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02311-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502311-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244663");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040709.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'protobuf' package(s) announced via the SUSE-SU-2025:02311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for protobuf fixes the following issues:

- CVE-2025-4565: Fix parsing of untrusted Protocol Buffers data containing an arbitrary number of recursive groups or messages that can lead to crash due to RecursionError (bsc#1244663).");

  script_tag(name:"affected", value:"'protobuf' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit", rpm:"libprotobuf-lite25_1_0-32bit~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0", rpm:"libprotobuf25_1_0~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit", rpm:"libprotobuf25_1_0-32bit~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0", rpm:"libprotoc25_1_0~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit", rpm:"libprotoc25_1_0-32bit~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java", rpm:"protobuf-java~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java-bom", rpm:"protobuf-java-bom~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java-parent", rpm:"protobuf-java-parent~25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-protobuf", rpm:"python311-protobuf~4.25.1~150600.16.13.1", rls:"openSUSELeap15.6"))) {
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

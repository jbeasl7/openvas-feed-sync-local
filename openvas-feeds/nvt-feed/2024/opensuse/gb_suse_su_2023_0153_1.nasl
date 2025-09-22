# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833607");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-0056");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-03 17:42:52 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:03:10 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for haproxy (SUSE-SU-2023:0153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0153-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CSNSXPHAT4TRBKFJRIOFMCBVWDO2VU4H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the SUSE-SU-2023:0153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for haproxy fixes the following issues:

  - CVE-2023-0056: Fixed a server crash that could be triggered via a
       malformed HTTP/2 frame (bsc#1207181).");

  script_tag(name:"affected", value:"'haproxy' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debuginfo", rpm:"haproxy-debuginfo~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debugsource", rpm:"haproxy-debugsource~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debuginfo", rpm:"haproxy-debuginfo~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debugsource", rpm:"haproxy-debugsource~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debuginfo", rpm:"haproxy-debuginfo~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debugsource", rpm:"haproxy-debugsource~2.4.8+git0.d1f8d41e0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
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
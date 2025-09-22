# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856038");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-0727");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:53:24 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:31:33 +0000 (Mon, 25 Mar 2024)");
  script_name("openSUSE: Security Advisory for openssl (SUSE-SU-2024:0833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0833-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PC6AUPJLGDSNWJYA6VXGD3DUNY2IUNF6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the SUSE-SU-2024:0833-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_1 fixes the following issues:

  * CVE-2024-0727: Denial of service when processing a maliciously formatted
      PKCS12 file (bsc#1219243).

  ##");

  script_tag(name:"affected", value:"'openssl' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel-32bit", rpm:"libopenssl-1_1-devel-32bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-32bit", rpm:"libopenssl1_1-hmac-32bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit-debuginfo", rpm:"libopenssl1_1-32bit-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-doc", rpm:"openssl-1_1-doc~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-64bit", rpm:"libopenssl1_1-hmac-64bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-64bit", rpm:"libopenssl1_1-64bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-64bit-debuginfo", rpm:"libopenssl1_1-64bit-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel-64bit", rpm:"libopenssl-1_1-devel-64bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel-32bit", rpm:"libopenssl-1_1-devel-32bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-32bit", rpm:"libopenssl1_1-hmac-32bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit-debuginfo", rpm:"libopenssl1_1-32bit-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-doc", rpm:"openssl-1_1-doc~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-64bit", rpm:"libopenssl1_1-hmac-64bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-64bit", rpm:"libopenssl1_1-64bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-64bit-debuginfo", rpm:"libopenssl1_1-64bit-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel-64bit", rpm:"libopenssl-1_1-devel-64bit~1.1.1l~150400.7.63.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.1l~150400.7.63.1", rls:"openSUSELeapMicro5.4"))) {
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

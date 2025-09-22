# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0417");
  script_cve_id("CVE-2020-24455");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-03 20:26:12 +0000 (Wed, 03 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0417)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0417");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0417.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27412");
  script_xref(name:"URL", value:"https://github.com/tpm2-software/tpm2-tss/releases");
  script_xref(name:"URL", value:"https://github.com/tpm2-software/tpm2-tss/releases/tag/2.4.3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/KBRTMYDRPQBDGNADVXGI745WGT2MGVOO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2-tss' package(s) announced via the MGASA-2020-0417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FAPI PolicyPCR not instatiating correctly (CVE-2020-24455).

Note that all TPM object created with a PolicyPCR with the currentPcrs
and currentPcrsAndBank options have been created with an incorrect policy
that omits PCR checks. All such objects have to be recreated.

The tpm2-tss package has been updated to version 2.4.3, which includes a fix
for this issue and several other changes. See the upstream release
announcements for details.");

  script_tag(name:"affected", value:"'tpm2-tss' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tpm2-tss-devel", rpm:"lib64tpm2-tss-devel~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-esys0", rpm:"lib64tss2-esys0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-fapi0", rpm:"lib64tss2-fapi0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-mu0", rpm:"lib64tss2-mu0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-rc0", rpm:"lib64tss2-rc0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-sys0", rpm:"lib64tss2-sys0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-device0", rpm:"lib64tss2-tcti-device0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-mssim0", rpm:"lib64tss2-tcti-mssim0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tctildr0", rpm:"lib64tss2-tctildr0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtpm2-tss-devel", rpm:"libtpm2-tss-devel~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi0", rpm:"libtss2-fapi0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0", rpm:"libtss2-sys0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~2.4.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-tss", rpm:"tpm2-tss~2.4.3~1.mga7", rls:"MAGEIA7"))) {
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

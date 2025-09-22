# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01631.1");
  script_cve_id("CVE-2025-3416");
  script_tag(name:"creation_date", value:"2025-05-22 12:07:17 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-08 19:15:53 +0000 (Tue, 08 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01631-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01631-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501631-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242622");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039275.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 's390-tools' package(s) announced via the SUSE-SU-2025:01631-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for s390-tools rebuilds the existing package with the new 4k RSA secure boot key.

Security issues fixed:

- CVE-2025-3416: Fixed Use-After-Free in Md::fetch and Cipher::fetch in rust-openssl crate. (bsc#1242622)

Other issues:

- Added the new IBM z17 (9175) processor type");

  script_tag(name:"affected", value:"'s390-tools' package(s) on SUSE Linux Enterprise Server 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libekmfweb1", rpm:"libekmfweb1~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libekmfweb1-devel", rpm:"libekmfweb1-devel~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmipclient1", rpm:"libkmipclient1~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"osasnmpd", rpm:"osasnmpd~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools", rpm:"s390-tools~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-chreipl-fcp-mpath", rpm:"s390-tools-chreipl-fcp-mpath~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-genprotimg-data", rpm:"s390-tools-genprotimg-data~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-hmcdrvfs", rpm:"s390-tools-hmcdrvfs~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-zdsfs", rpm:"s390-tools-zdsfs~2.31.0~150400.7.31.1", rls:"SLES15.0SP4"))) {
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

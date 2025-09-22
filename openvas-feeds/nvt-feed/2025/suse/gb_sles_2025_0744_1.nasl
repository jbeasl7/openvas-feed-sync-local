# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0744.1");
  script_cve_id("CVE-2025-26465");
  script_tag(name:"creation_date", value:"2025-03-03 04:08:07 +0000 (Mon, 03 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-18 19:15:29 +0000 (Tue, 18 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0744-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250744-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237040");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020457.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh8.4' package(s) announced via the SUSE-SU-2025:0744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh8.4 fixes the following issues:

- CVE-2025-26465: Fixed a MitM attack against OpenSSH's VerifyHostKeyDNS-enabled client (bsc#1237040).

Other bugfixes:

- Fix usage of local accelerator cards via openssl-ibmca (bsc#1216474, bsc#1218871).
- Add patches from upstream to change the default value of UpdateHostKeys to Yes (unless VerifyHostKeyDNS is enabled) (bsc#1222831).
- Fix hostbased ssh login failing occasionally with 'signature unverified: incorrect signature' by fixing a typo in patch (bsc#1221123).
- For now we don't ship the ssh-keycat command, but we need the patch for the other SELinux infrastructure (bsc#1214788).
- Attempts to mitigate instances of secrets lingering in memory after a session exits (bsc#1213004, bsc#1213008, bsc#1186673).");

  script_tag(name:"affected", value:"'openssh8.4' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"openssh8.4", rpm:"openssh8.4~8.4p1~8.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh8.4-clients", rpm:"openssh8.4-clients~8.4p1~8.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh8.4-common", rpm:"openssh8.4-common~8.4p1~8.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh8.4-fips", rpm:"openssh8.4-fips~8.4p1~8.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh8.4-helpers", rpm:"openssh8.4-helpers~8.4p1~8.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh8.4-server", rpm:"openssh8.4-server~8.4p1~8.16.1", rls:"SLES12.0SP5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01884.1");
  script_cve_id("CVE-2024-2467");
  script_tag(name:"creation_date", value:"2025-06-13 04:12:07 +0000 (Fri, 13 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-25 17:15:49 +0000 (Thu, 25 Apr 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01884-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501884-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221446");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040225.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Crypt-OpenSSL-RSA' package(s) announced via the SUSE-SU-2025:01884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-Crypt-OpenSSL-RSA fixes the following issues:

- CVE-2024-2467: Side-channel attack in PKCS#1 v1.5 padding mode (Marvin Attack)
 (bsc#1221446)");

  script_tag(name:"affected", value:"'perl-Crypt-OpenSSL-RSA' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Crypt-OpenSSL-RSA", rpm:"perl-Crypt-OpenSSL-RSA~0.28~150600.19.3.1", rls:"SLES15.0SP6"))) {
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

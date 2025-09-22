# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4303.1");
  script_cve_id("CVE-2024-9341", "CVE-2024-9407", "CVE-2024-9675", "CVE-2024-9676");
  script_tag(name:"creation_date", value:"2024-12-13 04:17:20 +0000 (Fri, 13 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 19:34:40 +0000 (Fri, 22 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4303-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244303-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232522");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019996.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2024:4303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

Security issues fixed:

- CVE-2024-9675: cache arbitrary directory mount (bsc#1231499)
- CVE-2024-9407: Improper Input Validation in bind-propagation Option of Dockerfile RUN --mount Instruction (bsc#1231208)
- CVE-2024-9676: symlink traversal vulnerability in the containers/storage library can cause denial of service (bsc#1231698)
- CVE-2024-9341: FIPS Crypto-Policy Directory Mounting Issue in containers/common Go Library (bsc#1231230)

Non-security issue fixed:

- default to slirp4netns on SLE instead of pasta (bsc#1232522)");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.35.4~150300.8.28.3", rls:"SLES15.0SP3"))) {
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

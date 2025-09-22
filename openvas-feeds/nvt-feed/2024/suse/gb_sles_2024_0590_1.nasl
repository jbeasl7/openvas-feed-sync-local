# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0590.1");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-5679", "CVE-2023-6516");
  script_tag(name:"creation_date", value:"2024-02-23 04:22:38 +0000 (Fri, 23 Feb 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:46 +0000 (Tue, 13 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0590-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0590-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240590-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219854");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017996.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2024:0590-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Validating DNS messages containing a lot of DNSSEC signatures
 could cause excessive CPU load, leading to a denial-of-service
 condition. This has been fixed. (CVE-2023-50387) [bsc#1219823]
* Preparing an NSEC3 closest encloser proof could cause excessive
 CPU load, leading to a denial-of-service condition. This has
 been fixed. (CVE-2023-50868) [bsc#1219826]
* Parsing DNS messages with many different names could cause
 excessive CPU load. This has been fixed. (CVE-2023-4408) [bsc#1219851]
* Specific queries could cause named to crash with an assertion
 failure when nxdomain-redirect was enabled. This has been
 fixed. (CVE-2023-5517) [bsc#1219852]
* A bad interaction between DNS64 and serve-stale could cause
 named to crash with an assertion failure, when both of these
 features were enabled. This has been fixed. (CVE-2023-5679)
 [bsc#1219853]
* Query patterns that continuously triggered cache database
 maintenance could cause an excessive amount of memory to be
 allocated, exceeding max-cache-size and potentially leading to
 all available memory on the host running named being exhausted.
 This has been fixed. (CVE-2023-6516) [bsc#1219854]

Removed Features:
* Support for using AES as the DNS COOKIE algorithm
 (cookie-algorithm aes,) has been deprecated and will be removed
 in a future release. Please use the current default,
 SipHash-2-4, instead.");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.48~150400.5.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.48~150400.5.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.48~150400.5.40.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.48~150400.5.40.1", rls:"SLES15.0SP4"))) {
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

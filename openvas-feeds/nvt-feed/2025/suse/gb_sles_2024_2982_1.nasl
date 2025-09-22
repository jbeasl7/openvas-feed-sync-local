# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2982.1");
  script_cve_id("CVE-2023-27043", "CVE-2024-0397", "CVE-2024-4032", "CVE-2024-5642", "CVE-2024-6923");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-27 18:50:57 +0000 (Thu, 27 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2982-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242982-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228780");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036645.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python311' package(s) announced via the SUSE-SU-2024:2982-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python311 fixes the following issues:

Security issues fixed:

- CVE-2024-6923: Fixed email header injection due to unquoted newlines (bsc#1228780)
- CVE-2024-5642: Removed support for anything but OpenSSL 1.1.1 or newer (bsc#1227233)
- CVE-2024-4032: Fixed incorrect IPv4 and IPv6 private ranges (bsc#1226448)

Non-security issues fixed:

- Fixed executable bits for /usr/bin/idle* (bsc#1227378).
- Improve python reproducible builds (bsc#1227999)
- Make pip and modern tools install directly in /usr/local when used by the user (bsc#1225660)
- %{profileopt} variable is set according to the variable %{do_profiling} (bsc#1227999)");

  script_tag(name:"affected", value:"'python311' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.9~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.9~150600.3.3.1", rls:"SLES15.0SP6"))) {
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

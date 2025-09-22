# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03260.1");
  script_cve_id("CVE-2025-46836");
  script_tag(name:"creation_date", value:"2025-09-19 04:08:00 +0000 (Fri, 19 Sep 2025)");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03260-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503260-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/142461");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041766.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-tools' package(s) announced via the SUSE-SU-2025:03260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for net-tools fixes the following issues:

Security issues fixed:

- CVE-2025-46836: missing bounds check in `get_name` may lead to a stack buffer overflow (bsc#1243581).
- Avoid unsafe use of `memcpy` in `ifconfig` (bsc#1248687).
- Prevent overflow in `ax25` and `netrom` (bsc#1248687).
- Fix stack buffer overflow in `parse_hex` (bsc#1248687).
- Fix stack buffer overflow in `proc_gen_fmt` (bsc#1248687).

Other issues fixed:

- Allow use of long interface names after CVE-2025-46836 fix, even if they are not accepted by the kernel (bsc#1248410).
- Fix netrom support.");

  script_tag(name:"affected", value:"'net-tools' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"net-tools", rpm:"net-tools~2.0+git20170221.479bb4a~150000.5.13.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-tools-lang", rpm:"net-tools-lang~2.0+git20170221.479bb4a~150000.5.13.1", rls:"SLES15.0SP6"))) {
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

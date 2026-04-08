# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20940.1");
  script_cve_id("CVE-2025-46836");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20940-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20940-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620940-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/142461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/430864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/544339");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045212.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-tools' package(s) announced via the SUSE-SU-2026:20940-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for net-tools fixes the following issues:

- Fix stack buffer overflow in parse_hex (bsc#1248687, GHSA-h667-qrp8-gj58).
- Fix stack-based buffer overflow in proc_gen_fmt (bsc#1248687, GHSA-w7jq-cmw2-cq59).
- Avoid unsafe memcpy in ifconfig (bsc#1248687).
- Prevent overflow in ax25 and netrom (bsc#1248687)
- Keep possibility to enter long interface names, even if they are
 not accepted by the kernel, because it was always possible up to
 CVE-2025-46836 fix. But issue a warning about an interface name
 concatenation (bsc#1248410).");

  script_tag(name:"affected", value:"'net-tools' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"net-tools", rpm:"net-tools~2.10~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-tools-lang", rpm:"net-tools-lang~2.10~160000.3.1", rls:"SLES16.0.0"))) {
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

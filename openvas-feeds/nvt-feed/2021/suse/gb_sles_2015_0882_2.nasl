# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0882.2");
  script_cve_id("CVE-2015-2170", "CVE-2015-2221", "CVE-2015-2222", "CVE-2015-2305", "CVE-2015-2668");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0882-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0882-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150882-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929192");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001386.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2015:0882-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ClamAV antivirus engine was updated to version 0.98.7 to fix several security and non security issues.

The following vulnerabilities were fixed (bsc#929192):
* CVE-2015-2170: Fix crash in upx decoder with crafted file. Discovered and patch supplied by Sebastian Andrzej Siewior.
* CVE-2015-2221: Fix infinite loop condition on crafted y0da cryptor file. Identified and patch suggested by Sebastian Andrzej Siewior.
* CVE-2015-2222: Fix crash on crafted petite packed file. Reported and patch supplied by Sebastian Andrzej Siewior.
* CVE-2015-2668: Fix an infinite loop condition on a crafted 'xz' archive file. This was reported by Dimitri Kirchner and Goulven Guiheux.
* CVE-2015-2305: Apply upstream patch for possible heap overflow in Henry Spencer's regex library.");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.7~13.1", rls:"SLES12.0"))) {
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

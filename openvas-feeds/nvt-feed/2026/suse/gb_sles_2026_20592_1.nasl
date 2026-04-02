# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20592.1");
  script_cve_id("CVE-2025-53816", "CVE-2025-53817");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 19:34:06 +0000 (Thu, 21 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20592-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620592-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249130");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024615.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '7zip' package(s) announced via the SUSE-SU-2026:20592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 7zip fixes the following issues:

- Update to 25.01 (boo#1249130)
 * The code for handling symbolic links has been changed to
 provide greater security when extracting files from archives
 * Command line switch -snld20 can be used to bypass default
 security checks when creating symbolic links.

- Update to 25.00:
 * bzip2 compression speed was increased by 15-40%.
 * deflate (zip/gz) compression speed was increased by 1-3%.
 * improved support for zip, cpio and fat archives.
 * CVE-2025-53816: Fixed input manipulation leading
 to heap buffer overflow (bsc#1246706)
 * CVE-2025-53817: Fixed null pointer dereference leading
 to denial of service (bsc#1246707)");

  script_tag(name:"affected", value:"'7zip' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"7zip", rpm:"7zip~25.01~160000.1.1", rls:"SLES16.0.0"))) {
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

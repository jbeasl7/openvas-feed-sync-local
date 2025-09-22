# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0005");
  script_cve_id("CVE-2014-8093", "CVE-2014-8098", "CVE-2014-8298");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0005");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0005.html");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/625511/");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2438-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14767");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14787");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-nvidia304, kmod-nvidia-current, nvidia304, nvidia-current' package(s) announced via the MGASA-2015-0005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nvidia304 and nvidia-current drivers fixes security issues:

The NVIDIA Linux Discrete GPU drivers before R304.125, R331.x before
R331.113, R340.x before R340.65, R343.x before R343.36, and R346.x
before R346.22, Linux for Tegra (L4T) driver before R21.2, and Chrome
OS driver before R40 allows remote attackers to cause a denial of
service (segmentation fault and X server crash) or possibly execute
arbitrary code via a crafted GLX indirect rendering protocol request
(CVE-2014-8093, CVE-2014-8098, CVE-2014-8298).

Note, the nvidia173 173.14.39 driver in Mageia 4 is also vulnerable
to this issue, but as it has reached EOL upstream it won't get any
fixes for this.

For nvidia-cuda-toolkit, it's safe to use with the fixed nvidia304
and nvidia-current drivers released as part of this update.");

  script_tag(name:"affected", value:"'kmod-nvidia304, kmod-nvidia-current, nvidia304, nvidia-current' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia-current", rpm:"dkms-nvidia-current~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia304", rpm:"dkms-nvidia304~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current", rpm:"nvidia-current~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-cuda-opencl", rpm:"nvidia-current-cuda-opencl~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-devel", rpm:"nvidia-current-devel~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-doc-html", rpm:"nvidia-current-doc-html~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.14.27-desktop-1.mga4", rpm:"nvidia-current-kernel-3.14.27-desktop-1.mga4~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.14.27-desktop586-1.mga4", rpm:"nvidia-current-kernel-3.14.27-desktop586-1.mga4~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.14.27-server-1.mga4", rpm:"nvidia-current-kernel-3.14.27-server-1.mga4~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304", rpm:"nvidia304~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-cuda-opencl", rpm:"nvidia304-cuda-opencl~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-devel", rpm:"nvidia304-devel~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-doc-html", rpm:"nvidia304-doc-html~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.14.27-desktop-1.mga4", rpm:"nvidia304-kernel-3.14.27-desktop-1.mga4~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.14.27-desktop586-1.mga4", rpm:"nvidia304-kernel-3.14.27-desktop586-1.mga4~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.14.27-server-1.mga4", rpm:"nvidia304-kernel-3.14.27-server-1.mga4~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia-current", rpm:"x11-driver-video-nvidia-current~331.113~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia304", rpm:"x11-driver-video-nvidia304~304.125~1.mga4.nonfree", rls:"MAGEIA4"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0115");
  script_cve_id("CVE-2023-28100", "CVE-2023-28101");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-18 13:37:35 +0000 (Tue, 18 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0115)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0115");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0115.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31688");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.12.8");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/03/17/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/03/17/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak' package(s) announced via the MGASA-2023-0115 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"If a malicious Flatpak app is run on a Linux virtual console such as
/dev/tty1, it can copy text from the virtual console and paste it back
into the virtual console's input buffer, from which the command might
be run by the user's shell after the Flatpak app has exited. This is
similar to CVE-2017-5226, but using the TIOCLINUX ioctl command instead
of TIOCSTI. (CVE-2023-28100)
Flatpak app with elevated permissions mayhide those permissions from
users of the 'flatpak(1)' command-line interface by setting other
permissions to crafted values that contain non-printable control
characters such as 'ESC'. (CVE-2023-28101)");

  script_tag(name:"affected", value:"'flatpak' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-tests", rpm:"flatpak-tests~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-devel", rpm:"lib64flatpak-devel~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-gir1.0", rpm:"lib64flatpak-gir1.0~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak0", rpm:"lib64flatpak0~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-devel", rpm:"libflatpak-devel~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-gir1.0", rpm:"libflatpak-gir1.0~1.12.8~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.12.8~1.mga8", rls:"MAGEIA8"))) {
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

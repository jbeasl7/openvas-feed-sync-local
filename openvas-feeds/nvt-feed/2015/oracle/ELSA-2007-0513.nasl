# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122659");
  script_cve_id("CVE-2006-4519", "CVE-2007-2949", "CVE-2007-3741");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:27 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2007-0513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux3|OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0513");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0513.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the ELSA-2007-0513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.3-20.9.el3]
 - validate bytesperline header field when loading PCX files (#247570)

 [1.2.3-20.8.el3]
 - reduce GIMP_MAX_IMAGE_SIZE to 2^18 to detect bogus image widths/heights
 (#247570)

 [1.2.3-20.7.el3]
 - replace gimp_error() by gimp_message()/gimp_quit() in a few plugins so
 they
 don't crash but gracefully exit when encountering error conditions
 - fix endianness issues in the PSP plugin to avoid it doing (seemingly)
 endless
 loops when loading images
 - fix endianness issues in the PCX plugin which cause it to not detect
 corrupt
 images

 [1.2.3-20.6.el3]
 - add ChangeLog entry to psd-invalid-dimensions patch (#247570)
 - validate size values read from files before using them to allocate
 memory in
 various file plugins (#247570, patch by Mukund Sivaraman and Rapha??l
 Quinet,
 adapted)
 - detect invalid image data when reading files in several plugins (#247570,
 patch by Sven Neumann and Rapha??l Quinet, adapted)
 - validate size values read from files before using them to allocate
 memory in
 the PSD and sunras plugins (#247570, patch by Mukund Sivaraman and Sven
 Neumann, partly adapted)
 - add safeguard to avoid crashes while loading corrupt PSD images (#247570,
 patch by Rapha??l Quinet, adapted)
 - convert spec file to UTF-8

 [1.2.3-20.5.el3]
 - use adapted upstream PSD fix by Sven Neumann (#244406)

 [1.2.3-20.4.el3]
 - refuse to open PSD files with insanely large dimensions (#244406)");

  script_tag(name:"affected", value:"'gimp' package(s) on Oracle Linux 3, Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux3") {

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~1.2.3~20.9.el3", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~1.2.3~20.9.el3", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-perl", rpm:"gimp-perl~1.2.3~20.9.el3", rls:"OracleLinux3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.0.5~7.0.7.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.0.5~7.0.7.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.2.13~2.0.7.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.2.13~2.0.7.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.2.13~2.0.7.el5", rls:"OracleLinux5"))) {
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

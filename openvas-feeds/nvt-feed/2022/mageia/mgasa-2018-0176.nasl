# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0176");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:07 +0000 (Wed, 14 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0176");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0176.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22762");
  script_xref(name:"URL", value:"https://downloadcenter.intel.com/download/27591/Linux-Processor-Microcode-Data-File?product=873");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2018-0176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides new microcode fixes and mitigations for Spectre
(CVE-2017-5715) for many Intel CPUs produced in the last 5 years.

So far the Intel microcode updates are for several processors from many
of Intel Haswell, Broadwell, Skylake, Kaby Lake, Coffee Lake, Gemini Lake,
Apollo Lake, Crystal Well and IVT platforms.

These updated microcodes should also fix the instabilities that some
users experienced with the earlier microcode updates released in
MGASA-2018-0079.

We will provide more microcode updates later on when they are made
available by Intel and Amd.

if you want to use this microcode on your current running kernel,
you need to re-create the initrd (initial ramdisk used at boot time),
you can do so by issuing the command 'dracut -f' as root, and reboot
your system

We also suggest that you check if there is updated BIOS and EFI
firmwares from your hardware vendor.

For a list of updated microcode revisions, read the referened Intel list page.");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20180312~1.mga6.nonfree", rls:"MAGEIA6"))) {
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

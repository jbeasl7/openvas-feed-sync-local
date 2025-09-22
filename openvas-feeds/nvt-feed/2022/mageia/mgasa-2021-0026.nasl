# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0026");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2021-0026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0026");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0026.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28050");
  script_xref(name:"URL", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5142/~/security-bulletin%3A-nvidia-gpu-display-driver---january-2021");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia390' package(s) announced via the MGASA-2021-0026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NVIDIA GPU Display Driver Linux contains a vulnerability in the kernel mode
layer (nvidia.ko) IOCTL in which user-mode clients can access legacy
privileged APIs, which may lead to denial of service, escalation of privileges,
and information disclosure (CVE-2021-1052).

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel
mode layer (nvidia.ko) IOCTL in which improper validation of a user pointer
may lead to denial of service (CVE-2021-1053).

NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel
mode layer (nvidia.ko) in which it does not completely honor operating system
file system permissions to provide GPU device-level isolation, which may
lead to denial of service or information disclosure (CVE-2021-1056).");

  script_tag(name:"affected", value:"'nvidia390' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia390", rpm:"dkms-nvidia390~390.141~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390", rpm:"nvidia390~390.141~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-cuda-opencl", rpm:"nvidia390-cuda-opencl~390.141~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-devel", rpm:"nvidia390-devel~390.141~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia390-doc-html", rpm:"nvidia390-doc-html~390.141~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia390", rpm:"x11-driver-video-nvidia390~390.141~1.mga7.nonfree", rls:"MAGEIA7"))) {
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

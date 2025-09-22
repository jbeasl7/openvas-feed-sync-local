# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845145");
  script_cve_id("CVE-2021-3760", "CVE-2021-3772", "CVE-2021-42327", "CVE-2021-42739", "CVE-2021-43056", "CVE-2021-43267", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-12-01 02:00:42 +0000 (Wed, 01 Dec 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 18:15:22 +0000 (Thu, 04 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-5165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5165-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5165-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.14' package(s) announced via the USN-5165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NFC subsystem in the Linux kernel contained a
use-after-free vulnerability in its NFC Controller Interface (NCI)
implementation. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2021-3760)

It was discovered that the SCTP protocol implementation in the Linux kernel
did not properly verify VTAGs in some situations. A remote attacker could
possibly use this to cause a denial of service (connection disassociation).
(CVE-2021-3772)

It was discovered that the AMD Radeon GPU driver in the Linux kernel did
not properly validate writes in the debugfs file system. A privileged
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-42327)

Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel
did not properly perform bounds checking in some situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-42739)

It was discovered that the KVM implementation for POWER8 processors in the
Linux kernel did not properly keep track if a wakeup event could be
resolved by a guest. An attacker in a guest VM could possibly use this to
cause a denial of service (host OS crash). (CVE-2021-43056)

It was discovered that the TIPC Protocol implementation in the Linux kernel
did not properly validate MSG_CRYPTO messages in some situations. An
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-43267)

It was discovered that the ISDN CAPI implementation in the Linux kernel
contained a race condition in certain situations that could trigger an
array out-of-bounds bug. A privileged local attacker could possibly use
this to cause a denial of service or execute arbitrary code.
(CVE-2021-43389)");

  script_tag(name:"affected", value:"'linux-oem-5.14' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.14.0-1008-oem", ver:"5.14.0-1008.8", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.14.0.1008.8", rls:"UBUNTU20.04 LTS"))) {
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

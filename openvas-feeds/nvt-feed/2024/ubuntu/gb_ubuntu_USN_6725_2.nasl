# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6725.2");
  script_cve_id("CVE-2023-1194", "CVE-2023-32254", "CVE-2023-32258", "CVE-2023-38427", "CVE-2023-38430", "CVE-2023-38431", "CVE-2023-3867", "CVE-2023-46838", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52436", "CVE-2023-52438", "CVE-2023-52439", "CVE-2023-52441", "CVE-2023-52442", "CVE-2023-52443", "CVE-2023-52444", "CVE-2023-52445", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52454", "CVE-2023-52456", "CVE-2023-52457", "CVE-2023-52458", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52467", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52480", "CVE-2023-52609", "CVE-2023-52610", "CVE-2023-52612", "CVE-2024-22705", "CVE-2024-23850", "CVE-2024-23851", "CVE-2024-24860", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26591", "CVE-2024-26597", "CVE-2024-26598", "CVE-2024-26631", "CVE-2024-26633");
  script_tag(name:"creation_date", value:"2024-04-17 04:10:18 +0000 (Wed, 17 Apr 2024)");
  script_version("2024-04-18T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 16:09:38 +0000 (Thu, 27 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6725-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6725-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6725-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-aws-5.15' package(s) announced via the USN-6725-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel
did not properly validate certain data structure fields when parsing lease
contexts, leading to an out-of-bounds read vulnerability. A remote attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2023-1194)

Quentin Minster discovered that a race condition existed in the KSMBD
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A remote attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2023-32254)

It was discovered that a race condition existed in the KSMBD implementation
in the Linux kernel when handling session connections, leading to a use-
after-free vulnerability. A remote attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-32258)

It was discovered that the KSMBD implementation in the Linux kernel did not
properly validate buffer sizes in certain operations, leading to an integer
underflow and out-of-bounds read vulnerability. A remote attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information. (CVE-2023-38427)

Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel
did not properly validate SMB request protocol IDs, leading to a out-of-
bounds read vulnerability. A remote attacker could possibly use this to
cause a denial of service (system crash). (CVE-2023-38430)

Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel
did not properly validate packet header sizes in certain situations,
leading to an out-of-bounds read vulnerability. A remote attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information. (CVE-2023-38431)

It was discovered that the KSMBD implementation in the Linux kernel did not
properly handle session setup requests, leading to an out-of-bounds read
vulnerability. A remote attacker could use this to expose sensitive
information. (CVE-2023-3867)

Pratyush Yadav discovered that the Xen network backend implementation in
the Linux kernel did not properly handle zero length data request, leading
to a null pointer dereference vulnerability. An attacker in a guest VM
could possibly use this to cause a denial of service (host domain crash).
(CVE-2023-46838)

It was discovered that the IPv6 implementation of the Linux kernel did not
properly manage route cache memory usage. A remote attacker could use this
to cause a denial of service (memory exhaustion). (CVE-2023-52340)

It was discovered that the device mapper driver in the Linux kernel did not
properly validate target size during certain memory allocations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-52429, CVE-2024-23851)

Yang Chaoming ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws, linux-aws-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1057-aws", ver:"5.15.0-1057.63~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.15.0.1057.63~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1057-aws", ver:"5.15.0-1057.63", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-22.04", ver:"5.15.0.1057.58", rls:"UBUNTU22.04 LTS"))) {
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

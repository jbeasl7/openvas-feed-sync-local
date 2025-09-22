# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1061");
  script_cve_id("CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805", "CVE-2016-6489");
  script_tag(name:"creation_date", value:"2020-01-23 10:41:47 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-03 19:52:30 +0000 (Thu, 03 Mar 2016)");

  script_name("Huawei EulerOS: Security Advisory for nettle (EulerOS-SA-2016-1061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2016-1061");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2016-1061");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'nettle' package(s) announced via the EulerOS-SA-2016-1061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ecc_256_modp function in ecc-256.c in Nettle before 3.2 does not properly handle carry propagation and produces incorrect output in its implementation of the P-256 NIST elliptic curve, which allows attackers to have unspecified impact via unknown vectors, a different vulnerability than CVE-2015-8805.(CVE-2015-8803)

x86_64/ecc-384-modp.asm in Nettle before 3.2 does not properly handle carry propagation and produces incorrect output in its implementation of the P-384 NIST elliptic curve, which allows attackers to have unspecified impact via unknown vectors.(CVE-2015-8804)

The ecc_256_modq function in ecc-256.c in Nettle before 3.2 does not properly handle carry propagation and produces incorrect output in its implementation of the P-256 NIST elliptic curve, which allows attackers to have unspecified impact via unknown vectors, a different vulnerability than CVE-2015-8803.(CVE-2015-8805)

It was found that nettle's RSA and DSA decryption code was vulnerable to cache-related side channel attacks. An attacker could use this flaw to recover the private key from a co-located virtual-machine instance.(CVE-2016-6489)");

  script_tag(name:"affected", value:"'nettle' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"nettle", rpm:"nettle~2.7.1~8", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle-devel", rpm:"nettle-devel~2.7.1~8", rls:"EULEROS-2.0SP1"))) {
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

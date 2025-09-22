# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1168");
  script_cve_id("CVE-2017-10978", "CVE-2017-10983", "CVE-2017-10984", "CVE-2017-10985", "CVE-2017-10986", "CVE-2017-10987");
  script_tag(name:"creation_date", value:"2020-01-23 10:54:46 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 16:27:01 +0000 (Wed, 19 Jul 2017)");

  script_name("Huawei EulerOS: Security Advisory for freeradius (EulerOS-SA-2017-1168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1168");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1168");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'freeradius' package(s) announced via the EulerOS-SA-2017-1168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow leading to a heap-buffer overflow was found in the libnl library. An attacker could use this flaw to cause an application compiled with libnl to crash or possibly execute arbitrary code in the context of the user running such an application. (CVE-2017-0553)

An out-of-bounds read and write flaw was found in the way FreeRADIUS server handled RADIUS packets. A remote attacker could use this flaw to crash the FreeRADIUS server by sending a specially crafted RADIUS packet. (CVE-2017-10978)

A denial of service flaw was found in the way FreeRADIUS server handled certain attributes in request packets. A remote attacker could use this flaw to cause the FreeRADIUS server to enter an infinite loop, consume increasing amounts of memory resources, and ultimately crash by sending a specially crafted request packet. (CVE-2017-10985)

Multiple out-of-bounds read flaws were found in the way FreeRADIUS server handled decoding of DHCP packets. A remote attacker could use these flaws to crash the FreeRADIUS server by sending a specially crafted DHCP request. (CVE-2017-10986, CVE-2017-10987)

An out-of-bounds read flaw was found in the way FreeRADIUS server handled decoding of DHCP packets. A remote attacker could use this flaw to crash the FreeRADIUS server by sending a specially crafted DHCP request. (CVE-2017-10983)

Multiple out-of-bounds read flaws were found in the way FreeRADIUS server handled decoding of DHCP packets. A remote attacker could use these flaws to crash the FreeRADIUS server by sending a specially crafted DHCP request. (CVE-2017-10986, CVE-2017-10987)

An out-of-bounds write flaw was found in the way FreeRADIUS server handled certain attributes in request packets. A remote attacker could use this flaw to crash the FreeRADIUS server or to execute arbitrary code in the context of the FreeRADIUS server process by sending a specially crafted request packet. (CVE-2017-10984)");

  script_tag(name:"affected", value:"'freeradius' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~3.0.13~8", rls:"EULEROS-2.0SP2"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122641");
  script_cve_id("CVE-2007-1218", "CVE-2007-3798");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:00 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 22:06:00 +0000 (Fri, 12 Jan 2024)");

  script_name("Oracle: Security Advisory (ELSA-2007-0368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0368");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0368.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the ELSA-2007-0368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[14:3.9.4-11.el5.0.1]
- Modified libpcap-0.9.4/fad-getad.c to include linux/types.h if it includes linux/if_packet.h

[14:3.9.4-11.el5]
- fix buffer overflow in BGP dissector (#250294, CVE-2007-3798)

[14:3.9.4-10.el5]
- with -C option, drop root privileges before opening first savefile (#241677)

[14:3.9.4-9.el5]
- fix buffer overflow in 802.11 printer (#232347, CVE-2007-1218)
- fix return codes in arpwatch init script (#237779)");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"arpwatch", rpm:"arpwatch~2.1a13~18.el5.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap", rpm:"libpcap~0.9.4~11.el5.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap-devel", rpm:"libpcap-devel~0.9.4~11.el5.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~3.9.4~11.el5.0.1", rls:"OracleLinux5"))) {
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

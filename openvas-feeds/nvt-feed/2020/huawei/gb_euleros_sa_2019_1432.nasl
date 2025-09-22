# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1432");
  script_cve_id("CVE-2014-2856", "CVE-2014-3537", "CVE-2014-5030", "CVE-2014-5031", "CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159", "CVE-2017-18190");
  script_tag(name:"creation_date", value:"2020-01-23 11:45:47 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 17:59:11 +0000 (Wed, 14 Mar 2018)");

  script_name("Huawei EulerOS: Security Advisory for cups (EulerOS-SA-2019-1432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1432");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1432");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'cups' package(s) announced via the EulerOS-SA-2019-1432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A cross-site scripting flaw was found in the cups web templating engine. An attacker could use this flaw to bypass the default configuration settings that bind the CUPS scheduler to the 'localhost' or loopback interface.(CVE-2015-1159)

It was discovered that CUPS allowed certain users to create symbolic links in certain directories under /var/cache/cups/. A local user with the 'lp' group privileges could use this flaw to read the contents of arbitrary files on the system or, potentially, escalate their privileges on the system.(CVE-2014-5031)

A string reference count bug was found in cupsd, causing premature freeing of string objects. An attacker could submit a malicious print job that exploits this flaw to dismantle ACLs protecting privileged operations, allowing a replacement configuration file to be uploaded, which in turn allowed the attacker to run arbitrary code on the CUPS server.(CVE-2015-1158)

A cross-site scripting (XSS) flaw was found in the CUPS web interface. An attacker could use this flaw to perform a cross-site scripting attack against users of the CUPS web interface.(CVE-2014-2856)

A localhost.localdomain whitelist entry in valid_host() in scheduler/client.c in CUPS before 2.2.2 allows remote attackers to execute arbitrary IPP commands by sending POST requests to the CUPS daemon in conjunction with DNS rebinding. The localhost.localdomain name is often resolved via a DNS server (neither the OS nor the web browser is responsible for ensuring that localhost.localdomain is 127.0.0.1).(CVE-2017-18190)

It was discovered that CUPS allowed certain users to create symbolic links in certain directories under /var/cache/cups/. A local user with the 'lp' group privileges could use this flaw to read the contents of arbitrary files on the system or, potentially, escalate their privileges on the system.(CVE-2014-5030)

It was discovered that CUPS allowed certain users to create symbolic links in certain directories under /var/cache/cups/. A local user with the 'lp' group privileges could use this flaw to read the contents of arbitrary files on the system or, potentially, escalate their privileges on the system.(CVE-2014-3537)

An integer overflow flaw, leading to a heap-based buffer overflow, was found in the way CUPS handled compressed raster image files. An attacker could create a specially crafted image file that, when passed via the CUPS Raster filter, could cause the CUPS filter to crash.(CVE-2014-9679)");

  script_tag(name:"affected", value:"'cups' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.6.3~35.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
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

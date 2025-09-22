# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0342.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0342-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140342-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-certs' package(s) announced via the SUSE-SU-2014:0342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openssl-certs package was updated to match the certificates contained in the Mozilla NSS 3.15.4 release.

Following changes were done to the list of root CAs:

 * Distrust a sub-ca ('AC DG Tresor SSL') that issued google.com certificates. (bnc#854367)

Many CA updates from Mozilla:

Changes from upstream version 1.96:

 * Added: ACCVRAIZ1.pem (Spain) (all trusts)
 * Added: SG_TRUST_SERVICES_RACINE.pem (Singapore)
(email signing only)
 * Added: TWCA_Global_Root_CA.pem (Taiwanese) (all trusts)
 * Removed: Wells_Fargo_Root_CA.pem.

Changes from upstream version 1.95:

 * Added:
CA_Disig_Root_R1:2.9.0.195.3.154.238.80.144.110.40.crt
(server auth, code signing, email signing)
 * Added:
CA_Disig_Root_R2:2.9.0.146.184.136.219.176.138.193.99.crt
(server auth, code signing, email signing)
 * Added:
China_Internet_Network_Information_Center_EV_Certificates_Ro ot:2.4.72.159.0.1.crt (server auth)
 * Changed:
Digital_Signature_Trust_Co._Global_CA_1:2.4.54.112.21.150.cr t (removed code signing and server auth abilities)
 * Changed:
Digital_Signature_Trust_Co._Global_CA_3:2.4.54.110.211.206.c rt (removed code signing and server auth abilities)
 * Added:
D-TRUST_Root_Class_3_CA_2_2009:2.3.9.131.243.crt (server auth)
 * Added:
D-TRUST_Root_Class_3_CA_2_EV_2009:2.3.9.131.244.crt (server auth)
 * Removed:
Entrust.net_Premium_2048_Secure_Server_CA:2.4.56.99.185.102.
crt
 * Added:
Entrust.net_Premium_2048_Secure_Server_CA:2.4.56.99.222.248.
crt
 * Removed:
Equifax_Secure_eBusiness_CA_2:2.4.55.112.207.181.crt
 * Added: PSCProcert:2.1.11.crt (server auth, code signing, email signing)
 * Added:
Swisscom_Root_CA_2:2.16.30.158.40.232.72.242.229.239.195.124
.74.30.90.24.103.182.crt (server auth, code signing, email signing)
 * Added:
Swisscom_Root_EV_CA_2:2.17.0.242.250.100.226.116.99.211.141.
253.16.29.4.31.118.202.88.crt (server auth, code signing)
 * Changed:
TC_TrustCenter_Universal_CA_III:2.14.99.37.0.1.0.2.20.141.51
.21.2.228.108.244.crt (removed all abilities)
 * Added:
TURKTRUST_Certificate_Services_Provider_Root_2007:2.1.1.crt
(server auth, code signing)
 * Changed: TWCA_Root_Certification_Authority:2.1.1.crt
(added code signing ability)
 * Added: 'EE Certification Centre Root CA'
 * Added: 'T-TeleSec GlobalRoot Class 3'
 * Revoked mis-issued intermediate CAs from TURKTRUST.");

  script_tag(name:"affected", value:"'openssl-certs' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~1.96~0.18.1", rls:"SLES10.0SP4"))) {
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

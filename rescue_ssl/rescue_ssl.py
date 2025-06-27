#!/usr/bin/env python3
"""
Kubernetes API 서버 TLS 진단 스크립트
  1) VIP(또는 LB)로 N회 연결해서 인증서 지문 통계 출력
  2) 마스터 노드마다 SSH 접속 → apiserver.crt 지문·Issuer·SAN 출력
  3) VIP에서 관측된 지문 ↔ 노드 매핑

사용 예)
  python check_k8s_certs.py \
      --vip 10.10.32.48 --port 10443 --sni kubernetes \
      --masters master1,master2,master3 \
      --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa \
      --samples 30
"""
import argparse, socket, ssl, hashlib, textwrap, json, sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

import paramiko


# ------------------------------------------------------------
# 공통 함수
# ------------------------------------------------------------
def fingerprint_der(der_bytes: bytes) -> str:
    """DER 인증서를 SHA256 Fingerprint(AA:BB:…) 형식으로 반환"""
    hexed = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(a + b for a, b in zip(hexed[::2], hexed[1::2]))


def get_server_cert(host: str, port: int, servername: str = None, timeout: int = 3) -> bytes:
    """TLS Handshake 후 서버 인증서(der) 반환"""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=servername) as ssock:
            return ssock.getpeercert(binary_form=True)


def parse_pem_file(path: str) -> x509.Certificate:
    with open(path, "rb") as fp:
        return x509.load_pem_x509_certificate(fp.read(), backend=default_backend())


def format_san(cert: x509.Certificate) -> str:
    try:
        sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        return ", ".join(sans.get_values_for_type(x509.DNSName) +
                         sans.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        return "(no SAN)"


def ssh_run(host: str, user: str, key_path: str, cmd: str) -> str:
    key = paramiko.RSAKey.from_private_key_file(key_path)
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=user, pkey=key, timeout=5)
        _, stdout, stderr = ssh.exec_command(cmd)
        return stdout.read().decode() + stderr.read().decode()


# ------------------------------------------------------------
# 부분 1) VIP 대상 지문 분포 수집
# ------------------------------------------------------------
def collect_vip_fingerprints(vip: str, port: int, servername: str, samples: int) -> Counter:
    counts = Counter()
    for _ in range(samples):
        try:
            der = get_server_cert(vip, port, servername)
            counts[fingerprint_der(der)] += 1
        except Exception as e:
            counts[f"ERROR:{e}"] += 1
    return counts


# ------------------------------------------------------------
# 부분 2) 각 마스터 노드 인증서 정보 수집
# ------------------------------------------------------------
def collect_node_certs(hosts, user, key, cert_path="/etc/kubernetes/pki/apiserver.crt"):
    node_info = {}
    for h in hosts:
        try:
            pem = ssh_run(h, user, key, f"sudo cat {cert_path}")
            cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
            node_info[h] = {
                "fingerprint": fingerprint_der(cert.public_bytes(encoding=ssl.PEM)),
                "issuer": cert.issuer.rfc4514_string(),
                "notAfter": cert.not_valid_after.isoformat(),
                "san": format_san(cert)
            }
        except Exception as e:
            node_info[h] = {"error": str(e)}
    return node_info


# ------------------------------------------------------------
# 메인
# ------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    p.add_argument("--vip", required=True, help="VIP or LB 주소")
    p.add_argument("--port", type=int, default=6443)
    p.add_argument("--sni", default=None, help="SNI(servername) 값, 없으면 생략")
    p.add_argument("--samples", type=int, default=20, help="VIP 샘플 연결 횟수")
    p.add_argument("--masters", required=True,
                   help="콤마로 구분된 마스터 호스트/IP 리스트")
    p.add_argument("--ssh-user", required=True)
    p.add_argument("--ssh-key", type=Path, required=True)
    args = p.parse_args()

    print(f"\n[1] VIP {args.vip}:{args.port} 샘플 {args.samples}회 연결 중 ...")
    vip_counts = collect_vip_fingerprints(args.vip, args.port, args.sni, args.samples)
    for fp, cnt in vip_counts.items():
        print(f"  {cnt:>3}  {fp}")

    print(f"\n[2] 마스터 노드별 인증서 정보 수집 ...")
    nodes = [h.strip() for h in args.masters.split(",")]
    node_info = collect_node_certs(nodes, args.ssh_user, str(args.ssh_key))

    pad = max(len(n) for n in nodes)
    for n, info in node_info.items():
        if "error" in info:
            print(f"{n:<{pad}}  ERROR {info['error']}")
            continue
        print(f"{n:<{pad}}  {info['fingerprint']}")
        print(f"{'':<{pad}}  Issuer : {info['issuer']}")
        print(f"{'':<{pad}}  NotAfter: {info['notAfter']}")
        print(f"{'':<{pad}}  SAN    : {info['san']}\n")

    print("[3] 매핑 결과 -------------------------------------------")
    vip_set = {fp for fp in vip_counts if not fp.startswith("ERROR")}
    for n, info in node_info.items():
        tag = "MATCH" if info.get("fingerprint") in vip_set else "----"
        print(f"{n:<{pad}}  {info.get('fingerprint','ERR')[:20]}...  {tag}")

    print("\n✔  스크립트 완료. 위에서 MATCH 안 되는 노드가 '문제 인증서' 후보입니다.")


if __name__ == "__main__":
    main()
